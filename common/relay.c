/* relay — poll() loop tying sockets to mux streams. See relay.h. */
#include "relay.h"
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

/* ---- growable FIFO byte buffer (head index, no per-drain memmove) ---- */
typedef struct { uint8_t *data; size_t cap, head, len; } buf_t;

static int buf_append(buf_t *b, const uint8_t *p, size_t n) {
    if (n == 0) return 0;
    /* compact consumed prefix before growing */
    if (b->head > 0) {
        memmove(b->data, b->data + b->head, b->len - b->head);
        b->len -= b->head;
        b->head = 0;
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
static void buf_consume(buf_t *b, size_t n) {
    b->head += n;
    if (b->head >= b->len) { b->head = 0; b->len = 0; }
}
static void buf_free(buf_t *b) { free(b->data); b->data = NULL; b->cap = b->head = b->len = 0; }

/* ---- per-stream connection ---- */
typedef struct {
    int      used;
    int      sock;             /* socket fd, or -1                       */
    uint32_t sid;
    int      connecting;       /* edge-peer: backend connect in progress */
    int      sock_eof;         /* read EOF from the socket (-> FIN sent)  */
    int      stream_fin;       /* peer FIN'd the stream (no more m2s)     */
    int      send_blocked;     /* stream send window is full              */
    int      gone;             /* scheduled for teardown                  */
    buf_t    s2m;              /* socket -> mux pending (window-blocked)  */
    buf_t    m2s;              /* mux -> socket pending (socket-blocked)  */
} conn;

struct relay {
    int          tunnel_fd;
    mux_session *mux;
    relay_opts   opt;

    uint8_t      nonce[16];
    uint8_t      my_proof[SHA256_DIGEST_LEN];
    int          authed;

    /* conn slab + freelist */
    conn   *conns;
    size_t  conns_cap;
    int    *freelist; size_t free_n;

    /* sid -> conn index (open addressing) */
    int    *sidmap; size_t sidmap_cap; /* stores idx+1, 0 = empty */

    /* persistent inbound buffer: a partial frame (or input held back by the
     * event-queue soft cap) survives across reads. Sized to hold several
     * max-size frames (peers using this lib chunk DATA at MUX_MAX_DATA_FRAME). */
    uint8_t recv_buf[262144];
    size_t  recv_len;

    /* poll set, rebuilt each iteration */
    struct pollfd *pfd; void **owner; size_t pfd_cap;
};

static volatile int g_stop = 0;
void relay_request_stop(void) { g_stop = 1; }

/* sentinel owners for non-conn pollfds */
static int OWN_TUNNEL, OWN_LISTEN;

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
        for (size_t i = nc; i > r->conns_cap; i--)
            r->freelist[r->free_n++] = (int)(i - 1);
        r->conns_cap = nc;
    }
    int idx = r->freelist[--r->free_n];
    memset(&r->conns[idx], 0, sizeof r->conns[idx]);
    r->conns[idx].used = 1;
    r->conns[idx].sock = -1;
    return idx;
}

static void conn_release(relay *r, int idx) {
    r->conns[idx].used = 0;
    r->freelist[r->free_n++] = idx;
}

static size_t sid_mix(uint32_t sid, size_t mask) {
    uint64_t h = (uint64_t)sid * 0x9e3779b97f4a7c15ull;
    return (size_t)(h >> 32) & mask;
}

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
    size_t mask = r->sidmap_cap - 1;
    size_t i = sid_mix(sid, mask);
    while (r->sidmap[i]) i = (i + 1) & mask;
    r->sidmap[i] = idx + 1;
}

static int sidmap_get(relay *r, uint32_t sid) {
    if (r->sidmap_cap == 0) return -1;
    size_t mask = r->sidmap_cap - 1;
    size_t i = sid_mix(sid, mask);
    for (size_t p = 0; p <= mask; p++) {
        int v = r->sidmap[i];
        if (v == 0) return -1;
        if (r->conns[v - 1].used && r->conns[v - 1].sid == sid) return v - 1;
        i = (i + 1) & mask;
    }
    return -1;
}

static void sidmap_del(relay *r, uint32_t sid) {
    /* lazy: leave a hole; rebuilt entries skip dead conns via `used` check.
     * To keep probe chains valid we rehash the run after the deleted slot. */
    if (r->sidmap_cap == 0) return;
    size_t mask = r->sidmap_cap - 1;
    size_t i = sid_mix(sid, mask);
    for (size_t p = 0; p <= mask; p++) {
        int v = r->sidmap[i];
        if (v == 0) return;
        if (r->conns[v - 1].sid == sid) { r->sidmap[i] = 0; break; }
        i = (i + 1) & mask;
    }
    /* reinsert the following cluster */
    size_t j = (i + 1) & mask;
    while (r->sidmap[j]) {
        int v = r->sidmap[j] - 1;
        r->sidmap[j] = 0;
        size_t k = sid_mix(r->conns[v].sid, mask);
        while (r->sidmap[k]) k = (k + 1) & mask;
        r->sidmap[k] = v + 1;
        j = (j + 1) & mask;
    }
}

/* ---- teardown ---- */

static void conn_destroy(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (!c->used) return;
    if (c->sock >= 0) close(c->sock);
    sidmap_del(r, c->sid);
    buf_free(&c->s2m);
    buf_free(&c->m2s);
    conn_release(r, idx);
}

/* free a conn once both halves are fully drained/closed */
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
    r->tunnel_fd = tunnel_fd;
    r->opt = *opts;

    mux_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.init_window    = opts->init_window;
    cfg.session_window = opts->session_window;
    cfg.heartbeat_ms   = opts->heartbeat_ms ? opts->heartbeat_ms : 15000;
    cfg.weight         = opts->weight;
    if (opts->peer_id) { cfg.peer_id = (const uint8_t *)opts->peer_id; cfg.peer_id_len = strlen(opts->peer_id); }

    if (opts->token) {
        os_random(r->nonce, sizeof r->nonce);
        mux_auth_proof(opts->token, strlen(opts->token), r->nonce, sizeof r->nonce, r->my_proof);
        cfg.nonce = r->nonce; cfg.nonce_len = sizeof r->nonce;
        cfg.auth  = r->my_proof; cfg.auth_len = sizeof r->my_proof;
    } else {
        r->authed = 1; /* no token configured => accept */
    }

    r->mux = mux_session_new(&cfg, opts->role);
    if (!r->mux) { free(r); return NULL; }
    return r;
}

void relay_free(relay *r) {
    if (!r) return;
    for (size_t i = 0; i < r->conns_cap; i++)
        if (r->conns[i].used) conn_destroy(r, (int)i);
    mux_session_free(r->mux);
    free(r->conns); free(r->freelist);
    free(r->sidmap);
    free(r->pfd); free(r->owner);
    free(r);
}

/* ---- data movement ---- */

/* Push as much of a conn's m2s buffer to its socket as it will take, crediting
 * the peer for whatever lands. Returns -1 if the socket failed. */
static int flush_to_socket(relay *r, int idx) {
    conn *c = &r->conns[idx];
    while (buf_avail(&c->m2s) > 0) {
        ssize_t w = write(c->sock, buf_ptr(&c->m2s), buf_avail(&c->m2s));
        if (w > 0) {
            buf_consume(&c->m2s, (size_t)w);
            mux_consume(r->mux, c->sid, (size_t)w); /* app consumed -> WINDOW_UPDATE */
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;                      /* socket full: wait for POLLOUT */
        } else {
            return -1;                  /* hard error */
        }
    }
    /* peer half-closed and we've delivered everything: stop writing */
    if (c->stream_fin && buf_avail(&c->m2s) == 0 && !c->sock_eof)
        shutdown(c->sock, SHUT_WR);
    return 0;
}

/* Push a conn's s2m backlog into the mux stream (after a WRITABLE). */
static void flush_to_mux(relay *r, int idx) {
    conn *c = &r->conns[idx];
    while (buf_avail(&c->s2m) > 0) {
        int64_t w = mux_write(r->mux, c->sid, buf_ptr(&c->s2m), buf_avail(&c->s2m));
        if (w > 0) buf_consume(&c->s2m, (size_t)w);
        if (w <= 0) { c->send_blocked = 1; return; }
        if ((size_t)w < buf_avail(&c->s2m)) { c->send_blocked = 1; return; }
    }
    c->send_blocked = 0;
    if (c->sock_eof) {
        /* socket already hit EOF; FIN once the backlog is gone */
        mux_close(r->mux, c->sid);
    }
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
                mux_auth_proof(r->opt.token, strlen(r->opt.token),
                               e.u.hello.nonce, e.u.hello.nonce_len, expect);
                if (e.u.hello.auth_len == SHA256_DIGEST_LEN &&
                    ct_equal(expect, e.u.hello.auth, SHA256_DIGEST_LEN)) {
                    r->authed = 1;
                    fprintf(stderr, "[relay] tunnel authenticated (weight=%u)\n", e.u.hello.weight);
                } else {
                    fprintf(stderr, "[relay] AUTH FAILED — dropping tunnel\n");
                    mux_goaway(r->mux, MUX_CODE_REFUSED);
                    g_stop = 1;
                }
            } else {
                fprintf(stderr, "[relay] tunnel up (weight=%u, no auth)\n", e.u.hello.weight);
            }
            break;

        case MUX_EV_STREAM_OPENED:
            /* edge-peer side: a new logical stream -> dial the backend. */
            if (r->opt.backend_host)
                open_backend_conn(r, e.sid, e.u.opened.meta, e.u.opened.meta_len);
            else
                mux_reset(r->mux, e.sid, MUX_CODE_REFUSED); /* edge never accepts */
            break;

        case MUX_EV_STREAM_DATA: {
            int idx = sidmap_get(r, e.sid);
            if (idx < 0) break;
            conn *c = &r->conns[idx];
            buf_append(&c->m2s, e.u.data.data, e.u.data.data_len); /* copy: view dies next recv */
            if (!c->connecting) flush_to_socket(r, idx);
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
            r->conns[idx].gone = 1;
            conn_destroy(r, idx);
            break;
        }
        case MUX_EV_WRITABLE: {
            if (e.sid == MUX_SID_CONTROL) {
                for (size_t i = 0; i < r->conns_cap; i++)
                    if (r->conns[i].used && r->conns[i].send_blocked)
                        flush_to_mux(r, (int)i);
            } else {
                int idx = sidmap_get(r, e.sid);
                if (idx >= 0) flush_to_mux(r, idx);
            }
            break;
        }
        case MUX_EV_GOAWAY:
            fprintf(stderr, "[relay] peer GOAWAY reason=%u\n", e.u.goaway.reason);
            break;
        case MUX_EV_CAPACITY:
            /* balancing input for edge-peer; logged for now */
            fprintf(stderr, "[relay] peer CAPACITY weight=%u\n", e.u.capacity.weight);
            break;
        case MUX_EV_FATAL:
            fprintf(stderr, "[relay] session FATAL code=%u — tearing down\n", e.u.fatal.code);
            g_stop = 1;
            break;
        default: break;
        }
    }
}

/* edge-peer: dial the backend for an inbound stream. */
static void open_backend_conn(relay *r, uint32_t sid, const uint8_t *meta, size_t mlen) {
    (void)meta; (void)mlen;
    int fd = net_dial(r->opt.backend_host, r->opt.backend_port);
    if (fd < 0) { mux_reset(r->mux, sid, MUX_CODE_INTERNAL); return; }
    int idx = conn_alloc(r);
    if (idx < 0) { close(fd); mux_reset(r->mux, sid, MUX_CODE_INTERNAL); return; }
    conn *c = &r->conns[idx];
    c->sock = fd; c->sid = sid; c->connecting = 1;
    sidmap_set(r, sid, idx);
}

/* edge: accept a public socket and open a stream for it. */
static void accept_public(relay *r) {
    for (;;) {
        char peer[128];
        int fd = net_accept(r->opt.public_listen_fd, peer, sizeof peer);
        if (fd < 0) break;              /* EAGAIN: drained */
        if (!r->authed) { close(fd); continue; } /* tunnel not ready */
        int64_t sid = mux_open(r->mux, (const uint8_t *)peer, strlen(peer));
        if (sid < 0) { close(fd); continue; }
        int idx = conn_alloc(r);
        if (idx < 0) { close(fd); mux_reset(r->mux, (uint32_t)sid, MUX_CODE_INTERNAL); continue; }
        conn *c = &r->conns[idx];
        c->sock = fd; c->sid = (uint32_t)sid;
        sidmap_set(r, (uint32_t)sid, idx);
    }
}

/* a conn socket became readable: pull a chunk and push into the stream. */
static void on_sock_readable(relay *r, int idx) {
    conn *c = &r->conns[idx];
    if (buf_avail(&c->s2m) > 0) return;  /* still draining a backlog */
    uint8_t tmp[32768];
    for (;;) {
        ssize_t n = read(c->sock, tmp, sizeof tmp);
        if (n > 0) {
            int64_t w = mux_write(r->mux, c->sid, tmp, (size_t)n);
            if (w < 0) { c->gone = 1; conn_destroy(r, idx); return; }
            if ((size_t)w < (size_t)n) {
                buf_append(&c->s2m, tmp + w, (size_t)n - (size_t)w);
                c->send_blocked = 1;
                return;                  /* window full: stop reading */
            }
            /* else fully accepted; loop for more */
        } else if (n == 0) {             /* EOF: half-close toward the peer */
            c->sock_eof = 1;
            if (buf_avail(&c->s2m) == 0) mux_close(r->mux, c->sid);
            conn_maybe_finish(r, idx);
            return;
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
        c->connecting = 0;
    }
    if (flush_to_socket(r, idx) < 0) {
        mux_reset(r->mux, c->sid, MUX_CODE_INTERNAL);
        c->gone = 1; conn_destroy(r, idx); return;
    }
    conn_maybe_finish(r, idx);
}

/* ---- tunnel I/O ---- */

/* Drive mux_recv over the persistent buffer, draining events and sliding the
 * unconsumed tail to the front. Returns -1 on a fatal/closed session. */
static int pump_recv(relay *r) {
    int64_t c = mux_recv(r->mux, r->recv_buf, r->recv_len);
    handle_events(r);
    if (c < 0) return -1;
    if (c > 0) {
        r->recv_len -= (size_t)c;
        if (r->recv_len) memmove(r->recv_buf, r->recv_buf + (size_t)c, r->recv_len);
    }
    return 0;
}

static int tunnel_read(relay *r) {
    for (;;) {
        size_t space = sizeof r->recv_buf - r->recv_len;
        if (space == 0) {
            /* Buffer full: mux held input back at the event-queue soft cap.
             * handle_events (in pump_recv) drained the queue, so re-running
             * mux_recv now makes progress. */
            size_t before = r->recv_len;
            if (pump_recv(r) < 0) return -1;
            if (r->recv_len == before) return 0; /* no progress: yield to loop */
            continue;
        }
        ssize_t n = read(r->tunnel_fd, r->recv_buf + r->recv_len, space);
        if (n > 0) {
            r->recv_len += (size_t)n;
            if (pump_recv(r) < 0) return -1;
            if ((size_t)n < space) return 0;     /* socket drained */
        } else if (n == 0) {
            fprintf(stderr, "[relay] tunnel closed by peer\n");
            return -1;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
    }
}

static int tunnel_flush(relay *r) {
    size_t len = 0;
    const uint8_t *buf = mux_send_buf(r->mux, &len);
    while (len > 0) {
        ssize_t w = write(r->tunnel_fd, buf, len);
        if (w > 0) {
            mux_send_advance(r->mux, (size_t)w);
            buf = mux_send_buf(r->mux, &len);
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            return -1;
        }
    }
    return 0;
}

/* ---- main loop ---- */

static void pfd_reset(relay *r) { /* nothing persistent; rebuilt each iter */ (void)r; }

static void pfd_add(relay *r, size_t *n, int fd, short events, void *owner) {
    if (*n >= r->pfd_cap) {
        size_t nc = r->pfd_cap ? r->pfd_cap * 2 : 64;
        r->pfd   = (struct pollfd *)realloc(r->pfd, nc * sizeof *r->pfd);
        r->owner = (void **)realloc(r->owner, nc * sizeof *r->owner);
        r->pfd_cap = nc;
    }
    r->pfd[*n].fd = fd; r->pfd[*n].events = events; r->pfd[*n].revents = 0;
    r->owner[*n] = owner;
    (*n)++;
}

int relay_run(relay *r) {
    long next_timer = 0;
    while (!g_stop) {
        /* advance keepalive timers using a coarse monotonic clock */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
        uint64_t deadline = mux_on_timer(r->mux, now);
        handle_events(r);
        if (g_stop) break;
        tunnel_flush(r);

        int timeout = 1000;
        if (deadline != UINT64_MAX) {
            long d = (long)(deadline - now);
            timeout = d < 0 ? 0 : (d > 1000 ? 1000 : (int)d);
        }
        (void)next_timer;

        /* build poll set */
        pfd_reset(r);
        size_t n = 0;
        size_t out_len = mux_out_pending(r->mux);
        /* Stop reading the tunnel while our output backlog is high: this is the
         * host-side backpressure that keeps the core's out buffer bounded. */
        short tev = (out_len ? POLLOUT : 0);
        if (out_len < (4u * 1024u * 1024u))
            tev |= POLLIN;
        pfd_add(r, &n, r->tunnel_fd, tev, &OWN_TUNNEL);
        if (r->opt.public_listen_fd >= 0)
            pfd_add(r, &n, r->opt.public_listen_fd, POLLIN, &OWN_LISTEN);
        for (size_t i = 0; i < r->conns_cap; i++) {
            conn *c = &r->conns[i];
            if (!c->used || c->sock < 0) continue;
            short ev = 0;
            if (c->connecting) ev |= POLLOUT;
            else {
                if (!c->sock_eof && buf_avail(&c->s2m) == 0 && !c->send_blocked) ev |= POLLIN;
                if (buf_avail(&c->m2s) > 0) ev |= POLLOUT;
            }
            if (ev) pfd_add(r, &n, c->sock, ev, &r->conns[i]);
        }

        int rc = poll(r->pfd, (nfds_t)n, timeout);
        if (rc < 0) { if (errno == EINTR) continue; break; }

        for (size_t i = 0; i < n; i++) {
            short re = r->pfd[i].revents;
            if (!re) continue;
            void *ow = r->owner[i];
            if (ow == &OWN_TUNNEL) {
                if (re & (POLLIN | POLLHUP | POLLERR)) { if (tunnel_read(r) < 0) { g_stop = 1; break; } }
                if (re & POLLOUT) tunnel_flush(r);
            } else if (ow == &OWN_LISTEN) {
                accept_public(r);
            } else {
                conn *c = (conn *)ow;
                if (!c->used) continue;
                int idx = (int)(c - r->conns);
                if (re & POLLOUT) on_sock_writable(r, idx);
                if (c->used && (re & (POLLIN | POLLHUP | POLLERR))) on_sock_readable(r, idx);
            }
        }
        tunnel_flush(r);
    }
    tunnel_flush(r);
    return 0;
}
