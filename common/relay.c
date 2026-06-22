/* relay — event-driven loop tying sockets to mux streams. See relay.h.
 *
 * Uses evloop (epoll/kqueue) so one thread carries tens of thousands of public
 * sockets at O(ready) per wait. Each socket's interest (read/write) is updated
 * only when it actually changes, via a small dirty list, instead of rescanning
 * every connection each iteration. fd udata is the conn INDEX (the conn slab
 * reallocs, so pointers are unstable; indices are not).
 */
#include "relay.h"
#include "net.h"
#include "auth.h"
#include "evloop.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- growable FIFO byte buffer (head index, no per-drain memmove) ---- */
typedef struct { uint8_t *data; size_t cap, head, len; } buf_t;

static int buf_append(buf_t *b, const uint8_t *p, size_t n) {
    if (n == 0) return 0;
    if (b->head > 0) {
        memmove(b->data, b->data + b->head, b->len - b->head);
        b->len -= b->head; b->head = 0;
    }
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->len + n) nc *= 2;
        uint8_t *nd = (uint8_t *)realloc(b->data, nc);
        if (!nd) return -1;
        b->data = nd; b->cap = nc;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}
static size_t buf_avail(const buf_t *b) { return b->len - b->head; }
static const uint8_t *buf_ptr(const buf_t *b) { return b->data + b->head; }
static void buf_consume(buf_t *b, size_t n) { b->head += n; if (b->head >= b->len) { b->head = 0; b->len = 0; } }
static void buf_free(buf_t *b) { free(b->data); b->data = NULL; b->cap = b->head = b->len = 0; }

/* ---- per-stream connection ---- */
typedef struct {
    int      used;
    int      sock;
    uint32_t sid;
    int      connecting;
    int      sock_eof;
    int      stream_fin;
    int      send_blocked;
    int      gone;
    int      cur_r, cur_w;     /* interest currently registered in evloop */
    int      in_dirty;
    buf_t    s2m;
    buf_t    m2s;
} conn;

struct relay {
    int          tunnel_fd;
    mux_session *mux;
    relay_opts   opt;
    evloop      *loop;

    uint8_t      nonce[16];
    uint8_t      my_proof[SHA256_DIGEST_LEN];
    int          authed;
    int          tun_r, tun_w;  /* tunnel interest currently registered     */

    conn   *conns; size_t conns_cap;
    int    *freelist; size_t free_n;
    int    *sidmap; size_t sidmap_cap;

    int    *dirty; size_t dirty_n, dirty_cap;

    int     nactive;            /* edge: public conns currently open          */
    int     listen_paused;      /* edge: accept paused (at max_streams)        */

    uint8_t recv_buf[262144];
    size_t  recv_len;
};

static volatile int g_stop = 0;
void relay_request_stop(void) { g_stop = 1; }

/* fd udata tags: small integers (idx+TAG_BASE) for conns, distinct sentinels
 * for the tunnel and listener (real addresses, far above any index). */
static int OWN_TUNNEL, OWN_LISTEN;
#define UD_CONN(idx) ((void *)(intptr_t)((idx) + 1))
#define UD_IS_CONN(p) ((uintptr_t)(p) != (uintptr_t)&OWN_TUNNEL && (uintptr_t)(p) != (uintptr_t)&OWN_LISTEN)
#define UD_IDX(p)    ((int)(intptr_t)(p) - 1)

/* ---- slab / maps ---- */
static size_t pow2_ceil(size_t x) { size_t p = 16; while (p < x) p *= 2; return p; }

static int conn_alloc(relay *r) {
    if (r->free_n == 0) {
        size_t nc = r->conns_cap ? r->conns_cap * 2 : 64;
        conn *nco = (conn *)realloc(r->conns, nc * sizeof *nco);
        if (!nco) return -1;
        int *nf = (int *)realloc(r->freelist, nc * sizeof *nf);
        if (!nf) return -1;
        r->conns = nco; r->freelist = nf;
        memset(&r->conns[r->conns_cap], 0, (nc - r->conns_cap) * sizeof *nco);
        for (size_t i = nc; i > r->conns_cap; i--) r->freelist[r->free_n++] = (int)(i - 1);
        r->conns_cap = nc;
    }
    int idx = r->freelist[--r->free_n];
    memset(&r->conns[idx], 0, sizeof r->conns[idx]);
    r->conns[idx].used = 1; r->conns[idx].sock = -1;
    r->conns[idx].cur_r = r->conns[idx].cur_w = -1; /* force first evloop_set */
    return idx;
}
static void conn_release(relay *r, int idx) { r->conns[idx].used = 0; r->freelist[r->free_n++] = idx; }

static size_t sid_mix(uint32_t sid, size_t mask) { uint64_t h = (uint64_t)sid * 0x9e3779b97f4a7c15ull; return (size_t)(h >> 32) & mask; }
static void sidmap_set(relay *r, uint32_t sid, int idx) {
    if ((r->sidmap_cap == 0) || ((size_t)idx + 1) * 4 >= r->sidmap_cap * 3) {
        size_t nc = pow2_ceil(r->sidmap_cap ? r->sidmap_cap * 2 : 64);
        int *nm = (int *)calloc(nc, sizeof *nm);
        if (!nm) return;
        for (size_t i = 0; i < r->sidmap_cap; i++) {
            if (r->sidmap[i] == 0) continue;
            int v = r->sidmap[i] - 1;
            size_t j = sid_mix(r->conns[v].sid, nc - 1);
            while (nm[j]) j = (j + 1) & (nc - 1);
            nm[j] = v + 1;
        }
        free(r->sidmap); r->sidmap = nm; r->sidmap_cap = nc;
    }
    size_t mask = r->sidmap_cap - 1, i = sid_mix(sid, mask);
    while (r->sidmap[i]) i = (i + 1) & mask;
    r->sidmap[i] = idx + 1;
}
static int sidmap_get(relay *r, uint32_t sid) {
    if (!r->sidmap_cap) return -1;
    size_t mask = r->sidmap_cap - 1, i = sid_mix(sid, mask);
    for (size_t p = 0; p <= mask; p++) {
        int v = r->sidmap[i];
        if (v == 0) return -1;
        if (r->conns[v-1].used && r->conns[v-1].sid == sid) return v-1;
        i = (i + 1) & mask;
    }
    return -1;
}
static void sidmap_del(relay *r, uint32_t sid) {
    if (!r->sidmap_cap) return;
    size_t mask = r->sidmap_cap - 1, i = sid_mix(sid, mask);
    for (size_t p = 0; p <= mask; p++) {
        int v = r->sidmap[i];
        if (v == 0) return;
        if (r->conns[v-1].sid == sid) { r->sidmap[i] = 0; break; }
        i = (i + 1) & mask;
    }
    size_t j = (i + 1) & mask;
    while (r->sidmap[j]) {
        int v = r->sidmap[j] - 1; r->sidmap[j] = 0;
        size_t k = sid_mix(r->conns[v].sid, mask);
        while (r->sidmap[k]) k = (k + 1) & mask;
        r->sidmap[k] = v + 1; j = (j + 1) & mask;
    }
}

/* ---- interest management ---- */
static void conn_desired(const conn *c, int *wr, int *ww) {
    if (c->connecting) { *wr = 0; *ww = 1; return; }
    *wr = (!c->sock_eof && buf_avail(&c->s2m) == 0 && !c->send_blocked);
    *ww = (buf_avail(&c->m2s) > 0);
}
static void conn_apply_interest(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (!c->used || c->sock < 0) return;
    int wr, ww; conn_desired(c, &wr, &ww);
    if (wr == c->cur_r && ww == c->cur_w) return;
    c->cur_r = wr; c->cur_w = ww;
    evloop_set(r->loop, c->sock, wr, ww, UD_CONN(idx));
}
static void mark_dirty(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (c->in_dirty) return;
    c->in_dirty = 1;
    if (r->dirty_n >= r->dirty_cap) {
        size_t nc = r->dirty_cap ? r->dirty_cap * 2 : 64;
        r->dirty = (int *)realloc(r->dirty, nc * sizeof *r->dirty);
        r->dirty_cap = nc;
    }
    r->dirty[r->dirty_n++] = idx;
}
static void flush_dirty(relay *r) {
    for (size_t i = 0; i < r->dirty_n; i++) {
        int idx = r->dirty[i];
        conn *c = &r->conns[idx];
        if (c->used && c->in_dirty) { c->in_dirty = 0; conn_apply_interest(r, idx); }
    }
    r->dirty_n = 0;
}
static void update_tunnel_interest(relay *r) {
    size_t out_len = mux_out_pending(r->mux);
    int wr = out_len < (4u * 1024u * 1024u);   /* backpressure: pause reads when backlog high */
    int ww = out_len > 0;
    if (wr == r->tun_r && ww == r->tun_w) return;
    r->tun_r = wr; r->tun_w = ww;
    evloop_set(r->loop, r->tunnel_fd, wr, ww, &OWN_TUNNEL);
}

/* ---- teardown ---- */
static void conn_destroy(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (!c->used) return;
    if (c->sock >= 0) { evloop_del(r->loop, c->sock); close(c->sock); }
    sidmap_del(r, c->sid);
    buf_free(&c->s2m); buf_free(&c->m2s);
    c->in_dirty = 0;                            /* drop any stale dirty entry */
    conn_release(r, idx);
    /* edge: a public slot freed — resume accepting if we were at the cap */
    if (r->opt.public_listen_fd >= 0) {
        if (r->nactive > 0) r->nactive--;
        if (r->listen_paused && (r->opt.max_streams <= 0 || r->nactive < r->opt.max_streams)) {
            evloop_set(r->loop, r->opt.public_listen_fd, 1, 0, &OWN_LISTEN);
            r->listen_paused = 0;
            fprintf(stderr, "[relay] accept resumed (%d streams)\n", r->nactive);
        }
    }
}
static void conn_maybe_finish(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (c->gone) { conn_destroy(r, idx); return; }
    if (c->sock_eof && c->stream_fin && buf_avail(&c->m2s) == 0 && buf_avail(&c->s2m) == 0)
        conn_destroy(r, idx);
}

/* ---- session setup ---- */
relay *relay_new(int tunnel_fd, const relay_opts *opts) {
    relay *r = (relay *)calloc(1, sizeof *r);
    if (!r) return NULL;
    r->tunnel_fd = tunnel_fd; r->opt = *opts;
    r->tun_r = r->tun_w = -1;

    mux_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.init_window = opts->init_window; cfg.session_window = opts->session_window;
    cfg.heartbeat_ms = opts->heartbeat_ms ? opts->heartbeat_ms : 15000;
    cfg.weight = opts->weight;
    if (opts->peer_id) { cfg.peer_id = (const uint8_t *)opts->peer_id; cfg.peer_id_len = strlen(opts->peer_id); }
    if (opts->token) {
        os_random(r->nonce, sizeof r->nonce);
        mux_auth_proof(opts->token, strlen(opts->token), r->nonce, sizeof r->nonce, r->my_proof);
        cfg.nonce = r->nonce; cfg.nonce_len = sizeof r->nonce;
        cfg.auth = r->my_proof; cfg.auth_len = sizeof r->my_proof;
    } else r->authed = 1;

    r->mux = mux_session_new(&cfg, opts->role);
    if (!r->mux) { free(r); return NULL; }
    r->loop = evloop_new();
    if (!r->loop) { mux_session_free(r->mux); free(r); return NULL; }
    return r;
}
void relay_free(relay *r) {
    if (!r) return;
    for (size_t i = 0; i < r->conns_cap; i++) if (r->conns[i].used) conn_destroy(r, (int)i);
    if (r->loop) evloop_free(r->loop);
    mux_session_free(r->mux);
    free(r->conns); free(r->freelist); free(r->sidmap); free(r->dirty);
    free(r);
}

/* ---- data movement ---- */
static int flush_to_socket(relay *r, int idx) {
    conn *c = &r->conns[idx];
    while (buf_avail(&c->m2s) > 0) {
        ssize_t w = write(c->sock, buf_ptr(&c->m2s), buf_avail(&c->m2s));
        if (w > 0) { buf_consume(&c->m2s, (size_t)w); mux_consume(r->mux, c->sid, (size_t)w); }
        else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else return -1;
    }
    if (c->stream_fin && buf_avail(&c->m2s) == 0 && !c->sock_eof) shutdown(c->sock, SHUT_WR);
    mark_dirty(r, idx);
    return 0;
}
static void flush_to_mux(relay *r, int idx) {
    conn *c = &r->conns[idx];
    while (buf_avail(&c->s2m) > 0) {
        int64_t w = mux_write(r->mux, c->sid, buf_ptr(&c->s2m), buf_avail(&c->s2m));
        if (w > 0) buf_consume(&c->s2m, (size_t)w);
        if (w <= 0) { c->send_blocked = 1; mark_dirty(r, idx); return; }
        if ((size_t)w < buf_avail(&c->s2m)) { c->send_blocked = 1; mark_dirty(r, idx); return; }
    }
    c->send_blocked = 0;
    if (c->sock_eof) mux_close(r->mux, c->sid);
    mark_dirty(r, idx);
}

/* ---- mux event handling ---- */
static void open_backend_conn(relay *r, uint32_t sid, const uint8_t *meta, size_t mlen);

static void handle_events(relay *r) {
    mux_event e;
    while (mux_next_event(r->mux, &e)) {
        switch (e.type) {
        case MUX_EV_PEER_HELLO:
            if (r->opt.token) {
                uint8_t expect[SHA256_DIGEST_LEN];
                mux_auth_proof(r->opt.token, strlen(r->opt.token), e.u.hello.nonce, e.u.hello.nonce_len, expect);
                if (e.u.hello.auth_len == SHA256_DIGEST_LEN && ct_equal(expect, e.u.hello.auth, SHA256_DIGEST_LEN)) {
                    r->authed = 1; fprintf(stderr, "[relay] tunnel authenticated (weight=%u)\n", e.u.hello.weight);
                } else { fprintf(stderr, "[relay] AUTH FAILED — dropping tunnel\n"); mux_goaway(r->mux, MUX_CODE_REFUSED); g_stop = 1; }
            } else fprintf(stderr, "[relay] tunnel up (weight=%u, no auth)\n", e.u.hello.weight);
            break;
        case MUX_EV_STREAM_OPENED:
            if (r->opt.backend_host) open_backend_conn(r, e.sid, e.u.opened.meta, e.u.opened.meta_len);
            else mux_reset(r->mux, e.sid, MUX_CODE_REFUSED);
            break;
        case MUX_EV_STREAM_DATA: {
            int idx = sidmap_get(r, e.sid);
            if (idx < 0) break;
            buf_append(&r->conns[idx].m2s, e.u.data.data, e.u.data.data_len);
            if (!r->conns[idx].connecting) flush_to_socket(r, idx);
            else mark_dirty(r, idx);
            break;
        }
        case MUX_EV_STREAM_CLOSED: {
            int idx = sidmap_get(r, e.sid);
            if (idx < 0) break;
            r->conns[idx].stream_fin = 1;
            if (!r->conns[idx].connecting) flush_to_socket(r, idx);
            conn_maybe_finish(r, idx);
            break;
        }
        case MUX_EV_STREAM_RESET: {
            int idx = sidmap_get(r, e.sid);
            if (idx < 0) break;
            r->conns[idx].gone = 1; conn_destroy(r, idx);
            break;
        }
        case MUX_EV_WRITABLE: {
            if (e.sid == MUX_SID_CONTROL) {
                for (size_t i = 0; i < r->conns_cap; i++)
                    if (r->conns[i].used && r->conns[i].send_blocked) flush_to_mux(r, (int)i);
            } else { int idx = sidmap_get(r, e.sid); if (idx >= 0) flush_to_mux(r, idx); }
            break;
        }
        case MUX_EV_GOAWAY: fprintf(stderr, "[relay] peer GOAWAY reason=%u\n", e.u.goaway.reason); break;
        case MUX_EV_CAPACITY: fprintf(stderr, "[relay] peer CAPACITY weight=%u\n", e.u.capacity.weight); break;
        case MUX_EV_FATAL: fprintf(stderr, "[relay] session FATAL code=%u\n", e.u.fatal.code); g_stop = 1; break;
        default: break;
        }
    }
}

static void open_backend_conn(relay *r, uint32_t sid, const uint8_t *meta, size_t mlen) {
    (void)meta; (void)mlen;
    int fd = net_dial(r->opt.backend_host, r->opt.backend_port);
    if (fd < 0) { mux_reset(r->mux, sid, MUX_CODE_INTERNAL); return; }
    int idx = conn_alloc(r);
    if (idx < 0) { close(fd); mux_reset(r->mux, sid, MUX_CODE_INTERNAL); return; }
    conn *c = &r->conns[idx];
    c->sock = fd; c->sid = sid; c->connecting = 1;
    sidmap_set(r, sid, idx);
    conn_apply_interest(r, idx);            /* register with the loop (POLLOUT) */
}

static void accept_public(relay *r) {
    for (;;) {
        /* Backpressure: at the stream cap, stop accepting and drop our read
         * interest on the listener so we don't spin on the backlog. Pending
         * clients wait in the kernel accept queue; conn_destroy resumes us. */
        if (r->opt.max_streams > 0 && r->nactive >= r->opt.max_streams) {
            if (!r->listen_paused) {
                evloop_set(r->loop, r->opt.public_listen_fd, 0, 0, &OWN_LISTEN);
                r->listen_paused = 1;
                fprintf(stderr, "[relay] accept paused at %d streams (cap)\n", r->nactive);
            }
            return;
        }
        char peer[128];
        int fd = net_accept(r->opt.public_listen_fd, peer, sizeof peer);
        if (fd < 0) break;
        if (!r->authed) { close(fd); continue; }
        int64_t sid = mux_open(r->mux, (const uint8_t *)peer, strlen(peer));
        if (sid < 0) { close(fd); continue; }
        int idx = conn_alloc(r);
        if (idx < 0) { close(fd); mux_reset(r->mux, (uint32_t)sid, MUX_CODE_INTERNAL); continue; }
        conn *c = &r->conns[idx];
        c->sock = fd; c->sid = (uint32_t)sid;
        sidmap_set(r, (uint32_t)sid, idx);
        r->nactive++;
        conn_apply_interest(r, idx);        /* register with the loop (POLLIN) */
    }
}

static void on_sock_readable(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (buf_avail(&c->s2m) > 0) return;
    uint8_t tmp[32768];
    for (;;) {
        ssize_t n = read(c->sock, tmp, sizeof tmp);
        if (n > 0) {
            int64_t w = mux_write(r->mux, c->sid, tmp, (size_t)n);
            if (w < 0) { c->gone = 1; conn_destroy(r, idx); return; }
            if ((size_t)w < (size_t)n) { buf_append(&c->s2m, tmp + w, (size_t)n - (size_t)w); c->send_blocked = 1; mark_dirty(r, idx); return; }
        } else if (n == 0) {
            c->sock_eof = 1;
            if (buf_avail(&c->s2m) == 0) mux_close(r->mux, c->sid);
            mark_dirty(r, idx); conn_maybe_finish(r, idx); return;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            c->gone = 1; conn_destroy(r, idx); return;
        }
    }
}
static void on_sock_writable(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (c->connecting) {
        int err = net_socket_error(c->sock);
        if (err != 0) { mux_reset(r->mux, c->sid, MUX_CODE_INTERNAL); c->gone = 1; conn_destroy(r, idx); return; }
        c->connecting = 0; mark_dirty(r, idx);
    }
    if (flush_to_socket(r, idx) < 0) { mux_reset(r->mux, c->sid, MUX_CODE_INTERNAL); c->gone = 1; conn_destroy(r, idx); return; }
    conn_maybe_finish(r, idx);
}

/* ---- tunnel I/O ---- */
static int pump_recv(relay *r) {
    int64_t c = mux_recv(r->mux, r->recv_buf, r->recv_len);
    handle_events(r);
    if (c < 0) return -1;
    if (c > 0) { r->recv_len -= (size_t)c; if (r->recv_len) memmove(r->recv_buf, r->recv_buf + (size_t)c, r->recv_len); }
    return 0;
}
static int tunnel_read(relay *r) {
    for (;;) {
        size_t space = sizeof r->recv_buf - r->recv_len;
        if (space == 0) { size_t before = r->recv_len; if (pump_recv(r) < 0) return -1; if (r->recv_len == before) return 0; continue; }
        ssize_t n = read(r->tunnel_fd, r->recv_buf + r->recv_len, space);
        if (n > 0) { r->recv_len += (size_t)n; if (pump_recv(r) < 0) return -1; if ((size_t)n < space) return 0; }
        else if (n == 0) { fprintf(stderr, "[relay] tunnel closed by peer\n"); return -1; }
        else { if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; return -1; }
    }
}
static int tunnel_flush(relay *r) {
    size_t len = 0; const uint8_t *buf = mux_send_buf(r->mux, &len);
    while (len > 0) {
        ssize_t w = write(r->tunnel_fd, buf, len);
        if (w > 0) { mux_send_advance(r->mux, (size_t)w); buf = mux_send_buf(r->mux, &len); }
        else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else return -1;
    }
    return 0;
}

/* ---- main loop ---- */
int relay_run(relay *r) {
    /* register the always-present fds */
    evloop_set(r->loop, r->tunnel_fd, 1, 0, &OWN_TUNNEL);
    r->tun_r = 1; r->tun_w = 0;
    if (r->opt.public_listen_fd >= 0)
        evloop_set(r->loop, r->opt.public_listen_fd, 1, 0, &OWN_LISTEN);

    ev_event evs[1024];
    while (!g_stop) {
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
        uint64_t deadline = mux_on_timer(r->mux, now);
        handle_events(r);
        if (g_stop) break;
        if (tunnel_flush(r) < 0) break;
        flush_dirty(r);
        update_tunnel_interest(r);

        int timeout = 1000;
        if (deadline != UINT64_MAX) { long d = (long)(deadline - now); timeout = d < 0 ? 0 : (d > 1000 ? 1000 : (int)d); }

        int n = evloop_wait(r->loop, evs, 1024, timeout);
        if (n < 0) break;

        for (int i = 0; i < n; i++) {
            void *ud = evs[i].udata;
            if (ud == &OWN_TUNNEL) {
                if (evs[i].readable) { if (tunnel_read(r) < 0) { g_stop = 1; break; } }
                if (!g_stop && evs[i].writable) tunnel_flush(r);
            } else if (ud == &OWN_LISTEN) {
                accept_public(r);
            } else {
                int idx = UD_IDX(ud);
                if (idx < 0 || (size_t)idx >= r->conns_cap || !r->conns[idx].used) continue;
                if (evs[i].writable) on_sock_writable(r, idx);
                if (r->conns[idx].used && evs[i].readable) on_sock_readable(r, idx);
            }
        }
        if (tunnel_flush(r) < 0) break;
        flush_dirty(r);
        update_tunnel_interest(r);
    }
    tunnel_flush(r);
    return 0;
}
