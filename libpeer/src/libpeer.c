/* libpeer — blocking, socket-shaped facade over a single mux tunnel.
 *
 * Architecture: one background I/O thread exclusively owns the mux_session and
 * the tunnel fd. App threads call the blocking lp_* API; they never touch the
 * session. They communicate with the I/O thread through per-stream byte buffers
 * and a "pending work" list, all under one mutex, and wake the thread (which is
 * usually parked in poll()) via a self-pipe. Condition variables back the
 * blocking semantics: lp_accept waits for an inbound stream, lp_read waits for
 * bytes, lp_write waits only when the send buffer is over its high-water mark.
 *
 * Stream objects are freed ONLY by the I/O thread, once both the protocol side
 * is done (FIN both ways, or RST) and the app has released its handle (lp_close).
 */
#include "libpeer.h"
#include "mux.h"
#include "net.h"
#include "auth.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- FIFO byte buffer (head index) ---- */
typedef struct { uint8_t *data; size_t cap, head, len; } buf_t;

static int buf_append(buf_t *b, const uint8_t *p, size_t n) {
    if (n == 0) return 0;
    if (b->head > 0 && b->head == b->len) { b->head = b->len = 0; }
    if (b->head > 0 && b->len + n > b->cap) {
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
static void buf_free(buf_t *b) { free(b->data); memset(b, 0, sizeof *b); }

#define LP_WBUF_HIGH (1u << 20)   /* lp_write blocks above this backlog */

/* ---- stream ---- */
struct lp_stream {
    lp_client *cli;
    uint32_t   sid;
    int        in_reg;          /* present in the sid registry           */

    buf_t      rbuf;            /* mux -> app                            */
    buf_t      wbuf;            /* app -> mux                            */
    size_t     consume_pending; /* app-read bytes awaiting mux_consume   */

    int        eof;             /* peer FIN seen (no more inbound)       */
    int        reset;           /* stream aborted                        */
    int        app_closed;      /* lp_close called                       */
    int        fin_sent;        /* we sent FIN                           */
    int        proto_done;      /* protocol fully closed                 */

    uint8_t   *meta; size_t meta_len;

    pthread_cond_t rcv;         /* signalled when rbuf/eof/reset change   */
    pthread_cond_t snd;         /* signalled when wbuf drains             */

    int        in_pending;
    lp_stream *pending_next;
    lp_stream *accept_next;     /* accept queue link                      */
    lp_stream *all_next, *all_prev;

    /* readiness (lp_poll) mode */
    int        ev_pending;      /* OR of LP_READABLE/LP_WRITABLE/LP_CLOSED */
    int        in_ready;
    int        want_writable;   /* a non-blocking write hit the high-water */
    lp_stream *ready_next;
};

/* ---- sid -> stream registry (open addressing) ---- */
typedef struct { uint32_t sid; lp_stream *st; uint8_t used; } reg_slot;

struct lp_client {
    lp_config cfg;
    char     *host, *token, *peer_id, *listen_addr;  /* owned copies        */

    pthread_t       io;
    pthread_mutex_t mtx;
    int             wake[2];            /* self-pipe                       */
    int             started;
    int             stopping;

    int           listen_fd;            /* bound once in listen mode; -1   */
    int           fd;                   /* tunnel; -1 when down            */
    mux_session  *mux;
    int           authed;
    uint8_t       nonce[16];
    uint8_t       proof[SHA256_DIGEST_LEN];

    reg_slot *reg; size_t reg_cap, reg_count;

    lp_stream *accept_head, *accept_tail;
    pthread_cond_t accept_cv;

    lp_stream *pending_head;            /* streams needing I/O-thread work */
    lp_stream *all_head;               /* every live stream               */

    /* readiness (lp_poll) mode */
    int        poll_mode;              /* enabled on first lp_fileno      */
    int        notify[2];              /* self-pipe; notify[0] = lp_fileno */
    int        notified;               /* coalesce: a byte is pending      */
    lp_stream *ready_head;             /* streams with ev_pending set      */

    uint8_t recv_buf[262144];
    size_t  recv_len;
};

/* ============================ registry ============================ */

static size_t reg_mix(uint32_t sid, size_t mask) {
    uint64_t h = (uint64_t)sid * 0x9e3779b97f4a7c15ull;
    return (size_t)(h >> 32) & mask;
}
static void reg_grow(lp_client *c, size_t want) {
    size_t nc = c->reg_cap ? c->reg_cap : 64;
    while (nc < want) nc *= 2;
    reg_slot *ns = (reg_slot *)calloc(nc, sizeof *ns);
    if (!ns) return;
    for (size_t i = 0; i < c->reg_cap; i++) {
        if (!c->reg[i].used) continue;
        size_t j = reg_mix(c->reg[i].sid, nc - 1);
        while (ns[j].used) j = (j + 1) & (nc - 1);
        ns[j] = c->reg[i];
    }
    free(c->reg); c->reg = ns; c->reg_cap = nc;
}
static void reg_put(lp_client *c, uint32_t sid, lp_stream *st) {
    if ((c->reg_count + 1) * 4 >= c->reg_cap * 3) reg_grow(c, (c->reg_count + 1) * 2);
    size_t mask = c->reg_cap - 1, i = reg_mix(sid, mask);
    while (c->reg[i].used) {
        if (c->reg[i].sid == sid) { c->reg[i].st = st; return; }
        i = (i + 1) & mask;
    }
    c->reg[i].used = 1; c->reg[i].sid = sid; c->reg[i].st = st; c->reg_count++;
    st->in_reg = 1;
}
static lp_stream *reg_get(lp_client *c, uint32_t sid) {
    if (!c->reg_cap) return NULL;
    size_t mask = c->reg_cap - 1, i = reg_mix(sid, mask);
    for (size_t p = 0; p <= mask; p++) {
        if (!c->reg[i].used) return NULL;
        if (c->reg[i].sid == sid) return c->reg[i].st;
        i = (i + 1) & mask;
    }
    return NULL;
}
static void reg_clear(lp_client *c) {       /* drop routing on reconnect */
    if (c->reg) memset(c->reg, 0, c->reg_cap * sizeof *c->reg);
    c->reg_count = 0;
    for (lp_stream *st = c->all_head; st; st = st->all_next) st->in_reg = 0;
}

/* ============================ wake / pending ============================ */

static void io_wake(lp_client *c) {
    uint8_t b = 1;
    ssize_t r = write(c->wake[1], &b, 1); (void)r;
}
static void pending_push(lp_client *c, lp_stream *st) {  /* caller holds mtx */
    if (st->in_pending) return;
    st->in_pending = 1;
    st->pending_next = c->pending_head;
    c->pending_head = st;
}

/* readiness mode: wake the app's event loop via the self-pipe (coalesced). */
static void notify_raise(lp_client *c) {     /* caller holds mtx */
    if (!c->poll_mode || c->notified) return;
    c->notified = 1;
    uint8_t b = 1;
    ssize_t r = write(c->notify[1], &b, 1); (void)r;
}
/* flag readiness event bits on a stream and queue it for lp_poll. */
static void ready_mark(lp_client *c, lp_stream *st, int bits) {  /* holds mtx */
    if (!c->poll_mode) return;
    st->ev_pending |= bits;
    if (!st->in_ready) { st->in_ready = 1; st->ready_next = c->ready_head; c->ready_head = st; }
    notify_raise(c);
}

/* ============================ stream lifecycle ============================ */

static lp_stream *stream_new(lp_client *c, uint32_t sid, const uint8_t *meta, size_t mlen) {
    lp_stream *st = (lp_stream *)calloc(1, sizeof *st);
    if (!st) return NULL;
    st->cli = c; st->sid = sid;
    pthread_cond_init(&st->rcv, NULL);
    pthread_cond_init(&st->snd, NULL);
    if (mlen) { st->meta = (uint8_t *)malloc(mlen); if (st->meta) { memcpy(st->meta, meta, mlen); st->meta_len = mlen; } }
    st->all_next = c->all_head;
    if (c->all_head) c->all_head->all_prev = st;
    c->all_head = st;
    return st;
}

/* Free a stream (I/O thread only), once proto-done and app-released. */
static void stream_try_free(lp_client *c, lp_stream *st) {
    if (!(st->proto_done && st->app_closed)) return;
    if (st->in_pending || st->in_ready) return;  /* freed after it drains */
    if (st->in_reg) {                        /* remove from registry */
        size_t mask = c->reg_cap - 1, i = reg_mix(st->sid, mask);
        for (size_t p = 0; p <= mask; p++) {
            if (c->reg[i].used && c->reg[i].sid == st->sid) { c->reg[i].used = 0; c->reg_count--; break; }
            if (!c->reg[i].used) break;
            i = (i + 1) & mask;
        }
        /* reinsert following cluster to preserve probe chains */
        size_t j = (i + 1) & mask;
        while (c->reg[j].used) {
            reg_slot s = c->reg[j]; c->reg[j].used = 0; c->reg_count--;
            reg_put(c, s.sid, s.st);
            j = (j + 1) & mask;
        }
    }
    if (st->all_prev) st->all_prev->all_next = st->all_next; else c->all_head = st->all_next;
    if (st->all_next) st->all_next->all_prev = st->all_prev;
    buf_free(&st->rbuf); buf_free(&st->wbuf); free(st->meta);
    pthread_cond_destroy(&st->rcv); pthread_cond_destroy(&st->snd);
    free(st);
}

/* ============================ I/O thread: mux events ============================ */

static void handle_events(lp_client *c) {   /* holds mtx */
    mux_event e;
    while (mux_next_event(c->mux, &e)) {
        switch (e.type) {
        case MUX_EV_PEER_HELLO:
            if (c->token) {
                uint8_t expect[SHA256_DIGEST_LEN];
                mux_auth_proof(c->token, strlen(c->token), e.u.hello.nonce, e.u.hello.nonce_len, expect);
                c->authed = (e.u.hello.auth_len == SHA256_DIGEST_LEN &&
                             ct_equal(expect, e.u.hello.auth, SHA256_DIGEST_LEN));
                if (!c->authed) { mux_goaway(c->mux, MUX_CODE_REFUSED); }
            } else c->authed = 1;
            break;
        case MUX_EV_STREAM_OPENED: {
            lp_stream *st = stream_new(c, e.sid, e.u.opened.meta, e.u.opened.meta_len);
            if (!st) { mux_reset(c->mux, e.sid, MUX_CODE_INTERNAL); break; }
            reg_put(c, e.sid, st);
            st->accept_next = NULL;          /* enqueue for lp_accept */
            if (c->accept_tail) c->accept_tail->accept_next = st; else c->accept_head = st;
            c->accept_tail = st;
            pthread_cond_signal(&c->accept_cv);
            notify_raise(c);                 /* poll mode: ACCEPT readiness */
            break;
        }
        case MUX_EV_STREAM_DATA: {
            lp_stream *st = reg_get(c, e.sid);
            if (!st) break;
            buf_append(&st->rbuf, e.u.data.data, e.u.data.data_len);
            pthread_cond_signal(&st->rcv);
            ready_mark(c, st, LP_READABLE);
            break;
        }
        case MUX_EV_STREAM_CLOSED: {
            lp_stream *st = reg_get(c, e.sid);
            if (!st) break;
            st->eof = 1;
            if (st->fin_sent) { st->proto_done = 1; }
            pthread_cond_signal(&st->rcv);
            ready_mark(c, st, LP_READABLE | LP_CLOSED);  /* wake reader to see EOF */
            stream_try_free(c, st);
            break;
        }
        case MUX_EV_STREAM_RESET: {
            lp_stream *st = reg_get(c, e.sid);
            if (!st) break;
            st->reset = 1; st->eof = 1; st->proto_done = 1;
            pthread_cond_signal(&st->rcv);
            pthread_cond_signal(&st->snd);
            ready_mark(c, st, LP_READABLE | LP_CLOSED);
            stream_try_free(c, st);
            break;
        }
        case MUX_EV_WRITABLE: {
            lp_stream *st = reg_get(c, e.sid);
            if (st && buf_avail(&st->wbuf) > 0) pending_push(c, st);
            break;
        }
        case MUX_EV_FATAL:
            /* tunnel is dead; the main loop notices c->mux being gone */
            break;
        default: break;
        }
    }
}

/* drain a stream's wbuf into the mux as the window allows. Does NOT free the
 * stream — process_pending owns the single free point. */
static void flush_wbuf(lp_client *c, lp_stream *st) {  /* holds mtx */
    while (buf_avail(&st->wbuf) > 0) {
        int64_t w = mux_write(c->mux, st->sid, st->wbuf.data + st->wbuf.head, buf_avail(&st->wbuf));
        if (w > 0) {
            st->wbuf.head += (size_t)w;
            if (st->wbuf.head == st->wbuf.len) { st->wbuf.head = st->wbuf.len = 0; }
        }
        if (w <= 0) break;                  /* window full or error */
    }
    if (buf_avail(&st->wbuf) <= LP_WBUF_HIGH / 2) {
        pthread_cond_signal(&st->snd);      /* room again for blocked writers */
        if (st->want_writable) { st->want_writable = 0; ready_mark(c, st, LP_WRITABLE); }
    }
}

/* perform queued app requests for one stream, then free it if it is fully done */
static void process_pending(lp_client *c, lp_stream *st) { /* holds mtx */
    if (st->consume_pending > 0) {
        mux_consume(c->mux, st->sid, st->consume_pending);
        st->consume_pending = 0;
    }
    if (buf_avail(&st->wbuf) > 0) flush_wbuf(c, st);
    /* send the FIN only once the send backlog is fully on the wire */
    if (st->app_closed && !st->fin_sent && buf_avail(&st->wbuf) == 0) {
        mux_close(c->mux, st->sid);
        st->fin_sent = 1;
        if (st->eof) st->proto_done = 1;
    }
    stream_try_free(c, st);                  /* single free point */
}

/* ============================ I/O thread: tunnel ============================ */

static int tunnel_flush(lp_client *c) {     /* holds mtx */
    size_t len = 0;
    const uint8_t *buf = mux_send_buf(c->mux, &len);
    while (len > 0) {
        ssize_t w = write(c->fd, buf, len);
        if (w > 0) { mux_send_advance(c->mux, (size_t)w); buf = mux_send_buf(c->mux, &len); }
        else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else return -1;
    }
    return 0;
}

static int tunnel_pump(lp_client *c) {      /* holds mtx */
    int64_t cc = mux_recv(c->mux, c->recv_buf, c->recv_len);
    handle_events(c);
    if (cc < 0) return -1;
    if (cc > 0) {
        c->recv_len -= (size_t)cc;
        if (c->recv_len) memmove(c->recv_buf, c->recv_buf + (size_t)cc, c->recv_len);
    }
    return 0;
}
static int tunnel_read(lp_client *c) {      /* holds mtx */
    for (;;) {
        size_t space = sizeof c->recv_buf - c->recv_len;
        if (space == 0) { size_t b = c->recv_len; if (tunnel_pump(c) < 0) return -1; if (c->recv_len == b) return 0; continue; }
        ssize_t n = read(c->fd, c->recv_buf + c->recv_len, space);
        if (n > 0) { c->recv_len += (size_t)n; if (tunnel_pump(c) < 0) return -1; if ((size_t)n < space) return 0; }
        else if (n == 0) return -1;
        else { if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; return -1; }
    }
}

/* tear down the live session, resetting every stream so blocked app calls return */
static void session_down(lp_client *c) {    /* holds mtx */
    for (lp_stream *st = c->all_head; st; st = st->all_next) {
        if (!st->proto_done) { st->reset = 1; st->eof = 1; st->proto_done = 1; }
        pthread_cond_signal(&st->rcv);
        pthread_cond_signal(&st->snd);
        ready_mark(c, st, LP_READABLE | LP_CLOSED);  /* wake poll-mode loops */
    }
    c->pending_head = NULL;
    for (lp_stream *st = c->all_head; st; st = st->all_next) st->in_pending = 0;
    reg_clear(c);
    if (c->mux) { mux_session_free(c->mux); c->mux = NULL; }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    c->authed = 0; c->recv_len = 0;
    /* free any streams the app already released */
    lp_stream *st = c->all_head;
    while (st) { lp_stream *nx = st->all_next; stream_try_free(c, st); st = nx; }
}

static int session_up(lp_client *c) {       /* holds mtx on entry; unlocks to wait */
    int listen_mode = (c->listen_addr != NULL);
    mux_role role = listen_mode ? MUX_ACCEPTOR : MUX_DIALER;
    int fd = -1, ok = 0;

    if (listen_mode) {
        if (c->listen_fd < 0) {
            c->listen_fd = net_listen_addr(c->listen_addr, 16);
            if (c->listen_fd < 0) { pthread_mutex_unlock(&c->mtx); struct timespec t={0,200000000L}; nanosleep(&t,NULL); pthread_mutex_lock(&c->mtx); return -1; }
        }
        int lfd = c->listen_fd;
        pthread_mutex_unlock(&c->mtx);
        for (;;) {
            struct pollfd p = { .fd = lfd, .events = POLLIN };
            int rc = poll(&p, 1, 300);
            if (rc < 0) { if (errno == EINTR) continue; break; }
            if (rc == 0) { if (__atomic_load_n(&c->stopping, __ATOMIC_RELAXED)) break; continue; }
            fd = net_accept(lfd, NULL, 0);
            ok = (fd >= 0);
            break;
        }
        pthread_mutex_lock(&c->mtx);
    } else {
        pthread_mutex_unlock(&c->mtx);
        fd = net_addr_is_unix(c->host) ? net_dial_addr(c->host)
                                       : net_dial(c->host, c->cfg.port);
        if (fd >= 0) {
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            for (;;) {
                int rc = poll(&p, 1, 300);
                if (rc < 0) { if (errno == EINTR) continue; break; }
                if (rc == 0) { if (__atomic_load_n(&c->stopping, __ATOMIC_RELAXED)) break; continue; }
                ok = (net_socket_error(fd) == 0);
                break;
            }
        }
        pthread_mutex_lock(&c->mtx);
    }
    if (!ok) { if (fd >= 0) close(fd); return -1; }

    mux_config mc; memset(&mc, 0, sizeof mc);
    mc.init_window = c->cfg.init_window; mc.session_window = c->cfg.session_window;
    mc.heartbeat_ms = c->cfg.heartbeat_ms ? c->cfg.heartbeat_ms : 15000;
    mc.weight = c->cfg.weight ? c->cfg.weight : 1;
    if (c->peer_id) { mc.peer_id = (const uint8_t *)c->peer_id; mc.peer_id_len = strlen(c->peer_id); }
    if (c->token) {
        os_random(c->nonce, sizeof c->nonce);
        mux_auth_proof(c->token, strlen(c->token), c->nonce, sizeof c->nonce, c->proof);
        mc.nonce = c->nonce; mc.nonce_len = sizeof c->nonce;
        mc.auth = c->proof; mc.auth_len = sizeof c->proof;
    }
    net_set_nonblock(fd);
    c->mux = mux_session_new(&mc, role);
    if (!c->mux) { close(fd); c->fd = -1; return -1; }
    c->fd = fd;
    return 0;
}

static void *io_main(void *arg) {
    lp_client *c = (lp_client *)arg;
    int backoff = 200;

    pthread_mutex_lock(&c->mtx);
    while (!c->stopping) {
        if (c->fd < 0) {
            if (session_up(c) != 0) {
                pthread_mutex_unlock(&c->mtx);
                struct timespec ts = { backoff / 1000, (backoff % 1000) * 1000000L };
                nanosleep(&ts, NULL);
                backoff = backoff < 8000 ? backoff * 2 : 8000;
                pthread_mutex_lock(&c->mtx);
                continue;
            }
            backoff = 200;
        }

        /* run queued app work, then flush */
        lp_stream *p = c->pending_head; c->pending_head = NULL;
        while (p) { lp_stream *nx = p->pending_next; p->in_pending = 0; process_pending(c, p); p = nx; }
        if (c->mux && tunnel_flush(c) < 0) { session_down(c); continue; }

        size_t out_pending = c->mux ? mux_out_pending(c->mux) : 0;
        struct pollfd pfd[2];
        pfd[0].fd = c->wake[0]; pfd[0].events = POLLIN; pfd[0].revents = 0;
        pfd[1].fd = c->fd;      pfd[1].events = 0;       pfd[1].revents = 0;
        if (out_pending < (4u << 20)) pfd[1].events |= POLLIN;
        if (out_pending) pfd[1].events |= POLLOUT;

        pthread_mutex_unlock(&c->mtx);
        int rc = poll(pfd, 2, 1000);
        pthread_mutex_lock(&c->mtx);
        if (rc < 0 && errno != EINTR) { session_down(c); continue; }

        if (pfd[0].revents & POLLIN) {
            uint8_t drain[256]; while (read(c->wake[0], drain, sizeof drain) > 0) {}
        }
        if (c->fd >= 0 && (pfd[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            if (tunnel_read(c) < 0) { session_down(c); continue; }
        }
        if (c->fd >= 0 && (pfd[1].revents & POLLOUT)) {
            if (tunnel_flush(c) < 0) { session_down(c); continue; }
        }
        /* advance keepalive timers */
        if (c->mux) {
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
            mux_on_timer(c->mux, now);
            handle_events(c);
            tunnel_flush(c);
        }
    }
    /* Graceful drain: flush queued work (FINs from lp_close, buffered writes)
     * and the output buffer before dropping the tunnel, so a worker that closes
     * a stream right before disconnecting still delivers its FIN/data. */
    if (c->mux && c->fd >= 0) {
        lp_stream *p = c->pending_head; c->pending_head = NULL;
        while (p) { lp_stream *nx = p->pending_next; p->in_pending = 0; process_pending(c, p); p = nx; }
        for (int i = 0; i < 100 && mux_out_pending(c->mux) > 0; i++) {
            if (tunnel_flush(c) < 0) break;
            if (mux_out_pending(c->mux) == 0) break;
            struct pollfd pf = { .fd = c->fd, .events = POLLOUT };
            pthread_mutex_unlock(&c->mtx);
            poll(&pf, 1, 20);
            pthread_mutex_lock(&c->mtx);
        }
    }
    session_down(c);
    /* wake any blocked acceptors */
    pthread_cond_broadcast(&c->accept_cv);
    pthread_mutex_unlock(&c->mtx);
    return NULL;
}

/* ============================ public API ============================ */

lp_client *lp_connect(const lp_config *cfg) {
    if (!cfg) return NULL;
    if (!cfg->listen_addr && !cfg->host) return NULL;  /* need one transport */
    lp_client *c = (lp_client *)calloc(1, sizeof *c);
    if (!c) return NULL;
    c->cfg = *cfg;
    c->host = cfg->host ? strdup(cfg->host) : NULL;
    c->listen_addr = cfg->listen_addr ? strdup(cfg->listen_addr) : NULL;
    c->token = cfg->token ? strdup(cfg->token) : NULL;
    c->peer_id = cfg->peer_id ? strdup(cfg->peer_id) : NULL;
    c->fd = -1;
    c->listen_fd = -1;
    c->notify[0] = c->notify[1] = -1;
    pthread_mutex_init(&c->mtx, NULL);
    pthread_cond_init(&c->accept_cv, NULL);
    if (pipe(c->wake) != 0) { free(c->host); free(c); return NULL; }
    net_set_nonblock(c->wake[0]); net_set_nonblock(c->wake[1]);
    if (pipe(c->notify) != 0) {            /* readiness self-pipe for lp_fileno */
        close(c->wake[0]); close(c->wake[1]); free(c->host); free(c); return NULL;
    }
    net_set_nonblock(c->notify[0]); net_set_nonblock(c->notify[1]);
    if (pthread_create(&c->io, NULL, io_main, c) != 0) {
        close(c->wake[0]); close(c->wake[1]); close(c->notify[0]); close(c->notify[1]);
        free(c->host); free(c);
        return NULL;
    }
    c->started = 1;
    return c;
}

void lp_disconnect(lp_client *c) {
    if (!c) return;
    pthread_mutex_lock(&c->mtx);
    c->stopping = 1;
    pthread_mutex_unlock(&c->mtx);
    io_wake(c);
    if (c->started) pthread_join(c->io, NULL);
    /* free any remaining streams (app abandoned them) */
    lp_stream *st = c->all_head;
    while (st) { lp_stream *nx = st->all_next; buf_free(&st->rbuf); buf_free(&st->wbuf);
                 free(st->meta); pthread_cond_destroy(&st->rcv); pthread_cond_destroy(&st->snd); free(st); st = nx; }
    if (c->listen_fd >= 0) close(c->listen_fd);
    free(c->reg); free(c->host); free(c->listen_addr); free(c->token); free(c->peer_id);
    close(c->wake[0]); close(c->wake[1]);
    if (c->notify[0] >= 0) close(c->notify[0]);
    if (c->notify[1] >= 0) close(c->notify[1]);
    pthread_mutex_destroy(&c->mtx); pthread_cond_destroy(&c->accept_cv);
    free(c);
}

lp_stream *lp_accept(lp_client *c) {
    if (!c) return NULL;
    pthread_mutex_lock(&c->mtx);
    while (!c->accept_head && !c->stopping)
        pthread_cond_wait(&c->accept_cv, &c->mtx);
    lp_stream *st = c->accept_head;
    if (st) {
        c->accept_head = st->accept_next;
        if (!c->accept_head) c->accept_tail = NULL;
        st->accept_next = NULL;
    }
    pthread_mutex_unlock(&c->mtx);
    return st;
}

ssize_t lp_read(lp_stream *s, void *buf, size_t n) {
    if (!s || n == 0) return 0;
    lp_client *c = s->cli;
    pthread_mutex_lock(&c->mtx);
    while (buf_avail(&s->rbuf) == 0 && !s->eof && !s->reset && !c->stopping)
        pthread_cond_wait(&s->rcv, &c->mtx);
    if (s->reset) { pthread_mutex_unlock(&c->mtx); return -1; }
    size_t avail = buf_avail(&s->rbuf);
    if (avail == 0) { pthread_mutex_unlock(&c->mtx); return 0; } /* EOF */
    size_t take = n < avail ? n : avail;
    memcpy(buf, s->rbuf.data + s->rbuf.head, take);
    s->rbuf.head += take;
    if (s->rbuf.head == s->rbuf.len) { s->rbuf.head = s->rbuf.len = 0; }
    s->consume_pending += take;             /* credit the peer via the I/O thread */
    pending_push(c, s);
    pthread_mutex_unlock(&c->mtx);
    io_wake(c);
    return (ssize_t)take;
}

ssize_t lp_write(lp_stream *s, const void *buf, size_t n) {
    if (!s || n == 0) return 0;
    lp_client *c = s->cli;
    pthread_mutex_lock(&c->mtx);
    /* backpressure: wait if the send backlog is already high */
    while (buf_avail(&s->wbuf) >= LP_WBUF_HIGH && !s->reset && !s->fin_sent && !c->stopping)
        pthread_cond_wait(&s->snd, &c->mtx);
    if (s->reset || s->fin_sent || c->stopping) { pthread_mutex_unlock(&c->mtx); return -1; }
    if (buf_append(&s->wbuf, (const uint8_t *)buf, n) != 0) { pthread_mutex_unlock(&c->mtx); return -1; }
    pending_push(c, s);
    pthread_mutex_unlock(&c->mtx);
    io_wake(c);
    return (ssize_t)n;
}

int lp_close(lp_stream *s) {
    if (!s) return -1;
    lp_client *c = s->cli;
    pthread_mutex_lock(&c->mtx);
    s->app_closed = 1;
    pending_push(c, s);
    pthread_mutex_unlock(&c->mtx);
    io_wake(c);
    return 0;
}

const uint8_t *lp_stream_meta(lp_stream *s, size_t *len) {
    if (len) *len = s ? s->meta_len : 0;
    return s ? s->meta : NULL;
}

/* ---------------------- readiness (event-loop) API ---------------------- */

int lp_fileno(lp_client *c) {
    if (!c) return -1;
    pthread_mutex_lock(&c->mtx);
    c->poll_mode = 1;                        /* start signalling readiness */
    int fd = c->notify[0];
    pthread_mutex_unlock(&c->mtx);
    return fd;
}

int lp_poll(lp_client *c, lp_event *out, int max) {
    if (!c || !out || max <= 0) return 0;
    pthread_mutex_lock(&c->mtx);
    /* drain the readiness pipe; the I/O thread re-arms it on the next event */
    uint8_t drain[256]; while (read(c->notify[0], drain, sizeof drain) > 0) {}
    c->notified = 0;

    int n = 0;
    /* ACCEPT first, so the app maps stream->handler before its READABLE event */
    while (n < max && c->accept_head) {
        lp_stream *st = c->accept_head;
        c->accept_head = st->accept_next;
        if (!c->accept_head) c->accept_tail = NULL;
        st->accept_next = NULL;
        out[n].stream = st; out[n].events = LP_ACCEPT;
        n++;
    }
    /* then per-stream READABLE/WRITABLE/CLOSED from the ready list */
    while (n < max && c->ready_head) {
        lp_stream *st = c->ready_head;
        c->ready_head = st->ready_next;
        st->ready_next = NULL; st->in_ready = 0;
        int bits = st->ev_pending;
        st->ev_pending = 0;
        if (st->app_closed) {                /* app no longer cares; reap it */
            stream_try_free(c, st);
            continue;
        }
        out[n].stream = st; out[n].events = bits;
        n++;
    }
    /* more left than fit: re-arm so the loop fires again */
    if (c->accept_head || c->ready_head) { c->notified = 0; notify_raise(c); }
    pthread_mutex_unlock(&c->mtx);
    return n;
}

ssize_t lp_read_nb(lp_stream *s, void *buf, size_t n) {
    if (!s || n == 0) return 0;
    lp_client *c = s->cli;
    pthread_mutex_lock(&c->mtx);
    if (s->reset) { pthread_mutex_unlock(&c->mtx); return -1; }
    size_t avail = buf_avail(&s->rbuf);
    if (avail == 0) {
        int eof = s->eof;
        pthread_mutex_unlock(&c->mtx);
        return eof ? 0 : LP_AGAIN;
    }
    size_t take = n < avail ? n : avail;
    memcpy(buf, s->rbuf.data + s->rbuf.head, take);
    s->rbuf.head += take;
    if (s->rbuf.head == s->rbuf.len) { s->rbuf.head = s->rbuf.len = 0; }
    s->consume_pending += take;
    pending_push(c, s);
    pthread_mutex_unlock(&c->mtx);
    io_wake(c);
    return (ssize_t)take;
}

ssize_t lp_write_nb(lp_stream *s, const void *buf, size_t n) {
    if (!s || n == 0) return 0;
    lp_client *c = s->cli;
    pthread_mutex_lock(&c->mtx);
    if (s->reset || s->fin_sent || c->stopping) { pthread_mutex_unlock(&c->mtx); return -1; }
    if (buf_avail(&s->wbuf) >= LP_WBUF_HIGH) {   /* full: ask for a WRITABLE event */
        s->want_writable = 1;
        pthread_mutex_unlock(&c->mtx);
        return LP_AGAIN;
    }
    if (buf_append(&s->wbuf, (const uint8_t *)buf, n) != 0) { pthread_mutex_unlock(&c->mtx); return -1; }
    pending_push(c, s);
    pthread_mutex_unlock(&c->mtx);
    io_wake(c);
    return (ssize_t)n;
}
