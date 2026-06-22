/* edge-peer stream router. See router.h.
 *
 * One upstream tunnel to the edge (we dial it; the edge opens streams) and a
 * pool of worker tunnels (we dial each; we open streams toward them). Each
 * inbound stream from the edge is SWRR-balanced onto a worker and spliced
 * stream<->stream. Flow control is coupled: a byte is credited on the source
 * session only once it has been accepted by the destination, so a slow worker
 * backpressures all the way to the public client. Worker death RSTs its
 * routes, which propagates upstream and closes the public connection.
 */
#include "router.h"
#include "mux.h"
#include "net.h"
#include "auth.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- FIFO byte buffer ---- */
typedef struct { uint8_t *data; size_t cap, head, len; } buf_t;
static int buf_append(buf_t *b, const uint8_t *p, size_t n) {
    if (n == 0) return 0;
    if (b->head == b->len) b->head = b->len = 0;
    if (b->head > 0 && b->len + n > b->cap) { memmove(b->data, b->data+b->head, b->len-b->head); b->len -= b->head; b->head = 0; }
    if (b->len + n > b->cap) { size_t nc = b->cap?b->cap:4096; while (nc<b->len+n) nc*=2; uint8_t*nd=realloc(b->data,nc); if(!nd) return -1; b->data=nd; b->cap=nc; }
    memcpy(b->data+b->len, p, n); b->len += n; return 0;
}
static size_t buf_avail(const buf_t *b){ return b->len-b->head; }
static void buf_free(buf_t *b){ free(b->data); memset(b,0,sizeof *b); }

/* ---- generic uint32 -> ptr map (open addressing) ---- */
typedef struct { uint32_t k; void *v; uint8_t used; } mslot;
typedef struct { mslot *s; size_t cap, count; } umap;
static size_t umix(uint32_t k, size_t mask){ uint64_t h=(uint64_t)k*0x9e3779b97f4a7c15ull; return (size_t)(h>>32)&mask; }
static void umap_grow(umap *m, size_t want){ size_t nc=m->cap?m->cap:64; while(nc<want)nc*=2; mslot*ns=calloc(nc,sizeof*ns); if(!ns)return; for(size_t i=0;i<m->cap;i++){ if(!m->s[i].used)continue; size_t j=umix(m->s[i].k,nc-1); while(ns[j].used)j=(j+1)&(nc-1); ns[j]=m->s[i]; } free(m->s); m->s=ns; m->cap=nc; }
static void umap_put(umap *m, uint32_t k, void *v){ if((m->count+1)*4>=m->cap*3) umap_grow(m,(m->count+1)*2); size_t mask=m->cap-1,i=umix(k,mask); while(m->s[i].used){ if(m->s[i].k==k){m->s[i].v=v;return;} i=(i+1)&mask; } m->s[i].used=1; m->s[i].k=k; m->s[i].v=v; m->count++; }
static void *umap_get(umap *m, uint32_t k){ if(!m->cap)return NULL; size_t mask=m->cap-1,i=umix(k,mask); for(size_t p=0;p<=mask;p++){ if(!m->s[i].used)return NULL; if(m->s[i].k==k)return m->s[i].v; i=(i+1)&mask; } return NULL; }
static void umap_del(umap *m, uint32_t k){ if(!m->cap)return; size_t mask=m->cap-1,i=umix(k,mask); for(size_t p=0;p<=mask;p++){ if(!m->s[i].used)return; if(m->s[i].k==k){m->s[i].used=0;m->count--;break;} i=(i+1)&mask; } size_t j=(i+1)&mask; while(m->s[j].used){ mslot s=m->s[j]; m->s[j].used=0; m->count--; umap_put(m,s.k,s.v); j=(j+1)&mask; } }

/* ---- one mux tunnel (upstream edge, or a worker) ---- */
typedef struct {
    char    *addr;
    int      fd;                /* -1 = down                              */
    int      connecting;
    mux_session *mux;
    int      ready;             /* peer HELLO seen + authed               */
    uint8_t  recv[262144]; size_t recv_len;
    uint64_t next_attempt;

    /* worker-only */
    int      is_worker;
    int      idx;               /* worker index                           */
    uint32_t weight;            /* advertised; 0 = draining/unknown        */
    long     swrr_cw;           /* SWRR current weight                     */
    uint32_t inflight;
    umap     routes;            /* sid -> route* (up_sid for an edge,      */
                                /* down_sid for a worker)                  */
    int      is_edge;           /* this tunnel is an upstream edge          */

    uint8_t  nonce[16], proof[32];
} conn_t;

/* ---- a spliced stream pair (one upstream edge <-> one worker) ---- */
typedef struct {
    int      edge_idx;          /* which upstream edge owns up_sid          */
    uint32_t up_sid;
    int      worker_idx;
    uint32_t down_sid;
    buf_t    u2w, w2u;          /* pending bytes awaiting dest window      */
    int      up_fin, down_fin;
    int      gone;
} route;

struct ep_state {
    ep_config cfg;
    conn_t   *edges; int nedges; /* upstream edge tunnels                  */
    conn_t   *wk; int nwk;       /* worker pool                            */
};

static volatile int g_stop = 0;
void ep_request_stop(void){ g_stop = 1; }

static uint64_t now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000u + (uint64_t)ts.tv_nsec/1000000u; }

/* ============================ auth ============================ */
static void conn_build_cfg(struct ep_state *e, conn_t *c, mux_config *mc) {
    memset(mc, 0, sizeof *mc);
    mc->init_window = e->cfg.init_window; mc->session_window = e->cfg.session_window;
    mc->heartbeat_ms = e->cfg.heartbeat_ms ? e->cfg.heartbeat_ms : 15000;
    mc->weight = 1;
    if (e->cfg.peer_id) { mc->peer_id = (const uint8_t*)e->cfg.peer_id; mc->peer_id_len = strlen(e->cfg.peer_id); }
    if (e->cfg.token) {
        os_random(c->nonce, sizeof c->nonce);
        mux_auth_proof(e->cfg.token, strlen(e->cfg.token), c->nonce, sizeof c->nonce, c->proof);
        mc->nonce = c->nonce; mc->nonce_len = sizeof c->nonce;
        mc->auth = c->proof; mc->auth_len = sizeof c->proof;
    }
}
static int check_auth(struct ep_state *e, const mux_event *ev) {
    if (!e->cfg.token) return 1;
    uint8_t expect[32];
    mux_auth_proof(e->cfg.token, strlen(e->cfg.token), ev->u.hello.nonce, ev->u.hello.nonce_len, expect);
    return ev->u.hello.auth_len == 32 && ct_equal(expect, ev->u.hello.auth, 32);
}

/* ============================ SWRR ============================ */
static int pick_worker(struct ep_state *e) {
    long total = 0; int best = -1; long bestcw = 0;
    for (int i = 0; i < e->nwk; i++) {
        conn_t *w = &e->wk[i];
        if (!w->ready || w->weight == 0) continue;
        w->swrr_cw += (long)w->weight;
        total += (long)w->weight;
        if (best < 0 || w->swrr_cw > bestcw) { best = i; bestcw = w->swrr_cw; }
    }
    if (best >= 0) e->wk[best].swrr_cw -= total;
    return best;
}

/* ============================ routes ============================ */
static route *route_new(struct ep_state *e, int eidx, uint32_t up_sid, int widx, uint32_t down_sid) {
    route *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    r->edge_idx = eidx; r->up_sid = up_sid; r->worker_idx = widx; r->down_sid = down_sid;
    umap_put(&e->edges[eidx].routes, up_sid, r);
    umap_put(&e->wk[widx].routes, down_sid, r);
    e->wk[widx].inflight++;
    return r;
}
static void route_free(struct ep_state *e, route *r) {
    if (r->edge_idx >= 0 && r->edge_idx < e->nedges)
        umap_del(&e->edges[r->edge_idx].routes, r->up_sid);
    if (r->worker_idx >= 0 && r->worker_idx < e->nwk) {
        umap_del(&e->wk[r->worker_idx].routes, r->down_sid);
        if (e->wk[r->worker_idx].inflight) e->wk[r->worker_idx].inflight--;
    }
    buf_free(&r->u2w); buf_free(&r->w2u);
    free(r);
}

/* Forward bytes src->dst, crediting src only for what dst accepts; buffer the
 * rest for a later flush on the dst's WRITABLE. */
static void fwd(mux_session *src, uint32_t src_sid, mux_session *dst, uint32_t dst_sid,
                buf_t *pend, const uint8_t *data, size_t len) {
    if (buf_avail(pend) > 0) { buf_append(pend, data, len); return; } /* keep order */
    int64_t w = mux_write(dst, dst_sid, data, len);
    if (w > 0) mux_consume(src, src_sid, (size_t)w);
    if (w < 0) w = 0;
    if ((size_t)w < len) buf_append(pend, data + w, len - (size_t)w);
}
static void flush_pend(mux_session *src, uint32_t src_sid, mux_session *dst, uint32_t dst_sid, buf_t *pend) {
    while (buf_avail(pend) > 0) {
        int64_t w = mux_write(dst, dst_sid, pend->data + pend->head, buf_avail(pend));
        if (w <= 0) break;
        mux_consume(src, src_sid, (size_t)w);
        pend->head += (size_t)w;
        if (pend->head == pend->len) pend->head = pend->len = 0;
    }
}

/* tear a route down, propagating RST/close to whichever side is still open */
static void route_kill(struct ep_state *e, route *r, int rst_up, int rst_down) {
    if (r->gone) return;
    r->gone = 1;
    if (rst_up && r->edge_idx >= 0 && r->edge_idx < e->nedges && e->edges[r->edge_idx].mux)
        mux_reset(e->edges[r->edge_idx].mux, r->up_sid, MUX_CODE_INTERNAL);
    if (rst_down && r->worker_idx >= 0 && e->wk[r->worker_idx].mux)
        mux_reset(e->wk[r->worker_idx].mux, r->down_sid, MUX_CODE_INTERNAL);
    route_free(e, r);
}

/* ============================ event handling ============================ */
static void on_up_events(struct ep_state *e, conn_t *ed) {
    int eidx = ed->idx;
    mux_event ev;
    while (mux_next_event(ed->mux, &ev)) {
        switch (ev.type) {
        case MUX_EV_PEER_HELLO:
            if (!check_auth(e, &ev)) { fprintf(stderr,"[ep] edge %d AUTH FAILED\n", eidx); mux_goaway(ed->mux, MUX_CODE_REFUSED); }
            else { ed->ready = 1; fprintf(stderr,"[ep] edge %d tunnel up (%s)\n", eidx, ed->addr); }
            break;
        case MUX_EV_STREAM_OPENED: {
            int widx = pick_worker(e);
            if (widx < 0) { mux_reset(ed->mux, ev.sid, MUX_CODE_REFUSED); break; } /* no worker */
            int64_t ds = mux_open(e->wk[widx].mux, ev.u.opened.meta, ev.u.opened.meta_len);
            if (ds < 0) { mux_reset(ed->mux, ev.sid, MUX_CODE_REFUSED); break; }
            route *r = route_new(e, eidx, ev.sid, widx, (uint32_t)ds);
            if (!r) { mux_reset(ed->mux, ev.sid, MUX_CODE_INTERNAL); mux_reset(e->wk[widx].mux,(uint32_t)ds,MUX_CODE_INTERNAL); }
            break;
        }
        case MUX_EV_STREAM_DATA: {
            route *r = umap_get(&ed->routes, ev.sid);
            if (!r || r->worker_idx < 0) break;
            fwd(ed->mux, r->up_sid, e->wk[r->worker_idx].mux, r->down_sid, &r->u2w,
                ev.u.data.data, ev.u.data.data_len);
            break;
        }
        case MUX_EV_WRITABLE: {              /* upstream send window reopened */
            route *r = umap_get(&ed->routes, ev.sid);
            if (r && r->worker_idx >= 0)
                flush_pend(e->wk[r->worker_idx].mux, r->down_sid, ed->mux, r->up_sid, &r->w2u);
            break;
        }
        case MUX_EV_STREAM_CLOSED: {
            route *r = umap_get(&ed->routes, ev.sid);
            if (!r || r->worker_idx < 0) break;
            flush_pend(ed->mux, r->up_sid, e->wk[r->worker_idx].mux, r->down_sid, &r->u2w);
            mux_close(e->wk[r->worker_idx].mux, r->down_sid);
            r->up_fin = 1;
            if (r->down_fin) route_free(e, r);
            break;
        }
        case MUX_EV_STREAM_RESET: {
            route *r = umap_get(&ed->routes, ev.sid);
            if (r) route_kill(e, r, 0, 1);
            break;
        }
        case MUX_EV_FATAL: break;
        default: break;
        }
    }
}

static void on_worker_events(struct ep_state *e, conn_t *w) {
    mux_event ev;
    while (mux_next_event(w->mux, &ev)) {
        switch (ev.type) {
        case MUX_EV_PEER_HELLO:
            if (!check_auth(e, &ev)) { fprintf(stderr,"[ep] worker %d AUTH FAILED\n", w->idx); mux_goaway(w->mux, MUX_CODE_REFUSED); }
            else { w->ready = 1; w->weight = ev.u.hello.weight ? ev.u.hello.weight : 1; w->swrr_cw = 0;
                   fprintf(stderr,"[ep] worker %d up (%s) weight=%u\n", w->idx, w->addr, w->weight); }
            break;
        case MUX_EV_CAPACITY:                 /* live weight / drain signal */
            w->weight = ev.u.capacity.weight;
            fprintf(stderr,"[ep] worker %d weight->%u\n", w->idx, w->weight);
            break;
        case MUX_EV_STREAM_DATA: {
            route *r = umap_get(&w->routes, ev.sid);
            if (!r || r->edge_idx < 0 || r->edge_idx >= e->nedges) break;
            mux_session *up = e->edges[r->edge_idx].mux; if (!up) break;
            fwd(w->mux, r->down_sid, up, r->up_sid, &r->w2u, ev.u.data.data, ev.u.data.data_len);
            break;
        }
        case MUX_EV_WRITABLE: {               /* worker send window reopened */
            route *r = umap_get(&w->routes, ev.sid);
            if (r && r->edge_idx >= 0 && r->edge_idx < e->nedges && e->edges[r->edge_idx].mux)
                flush_pend(e->edges[r->edge_idx].mux, r->up_sid, w->mux, r->down_sid, &r->u2w);
            break;
        }
        case MUX_EV_STREAM_CLOSED: {
            route *r = umap_get(&w->routes, ev.sid);
            if (!r || r->edge_idx < 0 || r->edge_idx >= e->nedges) break;
            mux_session *up = e->edges[r->edge_idx].mux; if (!up) break;
            flush_pend(w->mux, r->down_sid, up, r->up_sid, &r->w2u);
            mux_close(up, r->up_sid);
            r->down_fin = 1;
            if (r->up_fin) route_free(e, r);
            break;
        }
        case MUX_EV_STREAM_RESET: {
            route *r = umap_get(&w->routes, ev.sid);
            if (r) route_kill(e, r, 1, 0);
            break;
        }
        case MUX_EV_STREAM_OPENED:            /* workers never open toward us */
            mux_reset(w->mux, ev.sid, MUX_CODE_REFUSED);
            break;
        case MUX_EV_FATAL: break;
        default: break;
        }
    }
}

/* RST every route bound to a worker that just died, propagating upstream. */
static void drop_worker_routes(struct ep_state *e, conn_t *w) {
    for (size_t i = 0; i < w->routes.cap; i++) {
        if (!w->routes.s[i].used) continue;
        route *r = (route *)w->routes.s[i].v;
        if (r && !r->gone && r->edge_idx >= 0 && r->edge_idx < e->nedges && e->edges[r->edge_idx].mux)
            mux_reset(e->edges[r->edge_idx].mux, r->up_sid, MUX_CODE_INTERNAL);
    }
    /* free them (clears both maps) */
    for (;;) {
        route *r = NULL;
        for (size_t i = 0; i < w->routes.cap; i++) if (w->routes.s[i].used) { r = w->routes.s[i].v; break; }
        if (!r) break;
        r->gone = 1; route_free(e, r);
    }
}

/* RST every route bound to an edge that just died, propagating downstream. */
static void drop_edge_routes(struct ep_state *e, conn_t *ed) {
    for (size_t i = 0; i < ed->routes.cap; i++) {
        if (!ed->routes.s[i].used) continue;
        route *r = (route *)ed->routes.s[i].v;
        if (r && !r->gone && r->worker_idx >= 0 && r->worker_idx < e->nwk && e->wk[r->worker_idx].mux)
            mux_reset(e->wk[r->worker_idx].mux, r->down_sid, MUX_CODE_INTERNAL);
    }
    for (;;) {
        route *r = NULL;
        for (size_t i = 0; i < ed->routes.cap; i++) if (ed->routes.s[i].used) { r = ed->routes.s[i].v; break; }
        if (!r) break;
        r->gone = 1; route_free(e, r);
    }
}

/* ============================ tunnel I/O ============================ */
static int conn_flush(conn_t *c) {
    size_t len = 0; const uint8_t *b = mux_send_buf(c->mux, &len);
    while (len > 0) {
        ssize_t w = write(c->fd, b, len);
        if (w > 0) { mux_send_advance(c->mux, (size_t)w); b = mux_send_buf(c->mux, &len); }
        else if (w < 0 && (errno==EAGAIN||errno==EWOULDBLOCK)) break;
        else return -1;
    }
    return 0;
}
/* returns -1 if the session died */
static int conn_read(struct ep_state *e, conn_t *c) {
    for (;;) {
        size_t space = sizeof c->recv - c->recv_len;
        if (space == 0) {
            int64_t cc = mux_recv(c->mux, c->recv, c->recv_len);
            if (c->is_worker) on_worker_events(e, c); else on_up_events(e, c);
            if (cc < 0) return -1;
            if (cc > 0) { c->recv_len -= (size_t)cc; memmove(c->recv, c->recv+(size_t)cc, c->recv_len); }
            else return 0;
            continue;
        }
        ssize_t n = read(c->fd, c->recv + c->recv_len, space);
        if (n > 0) {
            c->recv_len += (size_t)n;
            int64_t cc = mux_recv(c->mux, c->recv, c->recv_len);
            if (c->is_worker) on_worker_events(e, c); else on_up_events(e, c);
            if (cc < 0) return -1;
            if (cc > 0) { c->recv_len -= (size_t)cc; if (c->recv_len) memmove(c->recv, c->recv+(size_t)cc, c->recv_len); }
            if ((size_t)n < space) return 0;
        } else if (n == 0) return -1;
        else { if (errno==EAGAIN||errno==EWOULDBLOCK) return 0; return -1; }
    }
}

static void conn_teardown(struct ep_state *e, conn_t *c) {
    if (c->is_worker) drop_worker_routes(e, c);
    else if (c->is_edge) drop_edge_routes(e, c);
    if (c->mux) { mux_session_free(c->mux); c->mux = NULL; }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    c->connecting = 0; c->ready = 0; c->recv_len = 0; c->inflight = 0;
    c->next_attempt = now_ms() + 500;
}

/* Begin (or finish) connecting a down tunnel. */
static void conn_tick_connect(struct ep_state *e, conn_t *c) {
    (void)e;
    if (c->fd >= 0) return;
    if (now_ms() < c->next_attempt) return;
    int fd = net_dial_addr(c->addr);
    if (fd < 0) { c->next_attempt = now_ms() + 1000; return; }
    c->fd = fd; c->connecting = 1;
}
static void conn_finish_connect(struct ep_state *e, conn_t *c) {
    if (net_socket_error(c->fd) != 0) { close(c->fd); c->fd = -1; c->next_attempt = now_ms()+1000; return; }
    net_set_nonblock(c->fd);
    net_set_keepalive(c->fd, 8, 3, 2);          /* reap dead edges/workers (~14s) */
    mux_config mc; conn_build_cfg(e, c, &mc);
    c->mux = mux_session_new(&mc, MUX_DIALER);  /* we dial both edge and workers */
    if (!c->mux) { close(c->fd); c->fd = -1; c->next_attempt = now_ms()+1000; return; }
    c->connecting = 0;
    conn_flush(c);                              /* push our HELLO */
}

/* ============================ main loop ============================ */
int ep_run(const ep_config *cfg) {
    struct ep_state E; memset(&E, 0, sizeof E);
    E.cfg = *cfg;
    E.nedges = cfg->nedges;
    E.edges = calloc((size_t)E.nedges, sizeof *E.edges);
    for (int i = 0; i < E.nedges; i++) { E.edges[i].addr = (char*)cfg->edges[i]; E.edges[i].fd = -1; E.edges[i].is_edge = 1; E.edges[i].idx = i; }
    E.nwk = cfg->nworkers;
    E.wk = calloc((size_t)E.nwk, sizeof *E.wk);
    for (int i = 0; i < E.nwk; i++) { E.wk[i].addr = (char*)cfg->workers[i]; E.wk[i].fd = -1; E.wk[i].is_worker = 1; E.wk[i].idx = i; }

    fprintf(stderr, "[ep] edges=%d workers=%d auth=%s\n", E.nedges, E.nwk, cfg->token?"on":"OFF");

    struct pollfd *pfd = NULL; conn_t **owner = NULL; size_t pcap = 0;

    while (!g_stop) {
        /* (re)connect any tunnels */
        for (int i = 0; i < E.nedges; i++) conn_tick_connect(&E, &E.edges[i]);
        for (int i = 0; i < E.nwk; i++) conn_tick_connect(&E, &E.wk[i]);

        /* keepalive + flush */
        uint64_t t = now_ms();
        for (int i = 0; i < E.nedges; i++) if (E.edges[i].mux) { mux_on_timer(E.edges[i].mux, t); on_up_events(&E, &E.edges[i]); conn_flush(&E.edges[i]); }
        for (int i = 0; i < E.nwk; i++) if (E.wk[i].mux) { mux_on_timer(E.wk[i].mux, t); on_worker_events(&E, &E.wk[i]); conn_flush(&E.wk[i]); }

        /* build poll set */
        size_t n = 0;
        #define ADD(C) do { if ((C)->fd >= 0) { \
            if (n >= pcap) { pcap = pcap?pcap*2:16; pfd=realloc(pfd,pcap*sizeof*pfd); owner=realloc(owner,pcap*sizeof*owner);} \
            short ev = 0; \
            if ((C)->connecting) ev = POLLOUT; \
            else { size_t op=(C)->mux?mux_out_pending((C)->mux):0; if (op < (4u<<20)) ev|=POLLIN; if (op) ev|=POLLOUT; } \
            pfd[n].fd=(C)->fd; pfd[n].events=ev; pfd[n].revents=0; owner[n]=(C); n++; } } while(0)
        for (int i = 0; i < E.nedges; i++) ADD(&E.edges[i]);
        for (int i = 0; i < E.nwk; i++) ADD(&E.wk[i]);
        #undef ADD

        int rc = poll(pfd, (nfds_t)n, 250);
        if (rc < 0) { if (errno==EINTR) continue; break; }

        for (size_t i = 0; i < n; i++) {
            if (!pfd[i].revents) continue;
            conn_t *c = owner[i];
            if (c->connecting) { if (pfd[i].revents & (POLLOUT|POLLERR|POLLHUP)) conn_finish_connect(&E, c); continue; }
            if (pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) { if (conn_read(&E, c) < 0) { conn_teardown(&E, c); continue; } }
            if (c->fd >= 0 && (pfd[i].revents & POLLOUT)) { if (conn_flush(c) < 0) { conn_teardown(&E, c); continue; } }
        }
        /* post-pass flush (routing may have produced output on peer sessions) */
        for (int i = 0; i < E.nedges; i++) if (E.edges[i].mux) conn_flush(&E.edges[i]);
        for (int i = 0; i < E.nwk; i++) if (E.wk[i].mux) conn_flush(&E.wk[i]);
    }

    /* teardown */
    for (int i = 0; i < E.nwk; i++) { conn_teardown(&E, &E.wk[i]); free(E.wk[i].routes.s); }
    for (int i = 0; i < E.nedges; i++) { conn_teardown(&E, &E.edges[i]); free(E.edges[i].routes.s); }
    free(E.edges); free(E.wk); free(pfd); free(owner);
    return 0;
}
