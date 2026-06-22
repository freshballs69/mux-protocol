/* libmux session state machine (sans-io) — see include/mux.h.
 *
 * This layers stream lifecycle, flow control, handshake and keepalive on
 * top of the framing codec in frame.c. It performs NO socket or clock I/O:
 * the host feeds it transport bytes (mux_recv) and time (mux_on_timer) and
 * pumps the produced bytes (mux_send_buf) and events (mux_next_event).
 *
 * Memory discipline: stream records live in a pre-sized open-addressing
 * table; the output buffer and event ring grow only to a high-water mark
 * and are then reused. The per-frame hot path performs no allocation.
 *
 * Flow control is HTTP/2-style and two-level:
 *   - per stream:      send_win / recv_win
 *   - per connection:  sess_send_win / sess_recv_win, carried on stream id 0
 * Every DATA byte is debited from BOTH the stream and the connection window,
 * so N streams can never collectively buffer more than the connection cap —
 * this is what makes 200k streams survivable in bounded memory.
 */
#include "mux.h"

#include <stdlib.h>
#include <string.h>

/* ---- big-endian helpers (byte-wise; mirror frame.c) ---- */
static inline void be_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v);
}
static inline uint32_t be_get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

/* ================================================================== */
/* Internal data structures                                           */
/* ================================================================== */

enum { SLOT_EMPTY = 0, SLOT_USED = 1, SLOT_TOMB = 2 };
enum { LIFE_OPEN = 0, LIFE_HCL_LOCAL = 1, LIFE_HCL_REMOTE = 2 };

typedef struct {
    uint32_t sid;
    uint8_t  slot;          /* SLOT_*                                      */
    uint8_t  life;          /* LIFE_* (valid when slot == SLOT_USED)       */
    uint8_t  send_blocked;  /* a write hit window 0; owed a WRITABLE event */
    int64_t  send_win;      /* bytes we may still send on this stream      */
    int64_t  recv_win;      /* bytes the peer may still send to us         */
    int64_t  recv_pending;  /* consumed, not yet credited (batched WU)     */
} mux_stream;

typedef struct { uint8_t  *buf; size_t cap, len, spos; } outbuf;
typedef struct { mux_event *ev; size_t cap, head, count; } evq;

struct mux_session {
    mux_role role;
    int      dead;          /* a FATAL has been raised; reject further ops */

    /* negotiated/config flow-control baselines */
    uint32_t init_window;       /* our per-stream recv window              */
    uint32_t session_window;    /* our connection recv window              */
    uint32_t max_streams;       /* our inbound concurrency cap             */
    uint32_t peer_init_window;  /* peer's per-stream recv window (our send) */
    uint32_t peer_max_streams;  /* peer's cap on our outbound opens        */

    /* connection-level flow control */
    int64_t  sess_send_win;
    int64_t  sess_recv_win;
    int64_t  sess_recv_pending;
    size_t   blocked_count;     /* streams currently flagged send_blocked    */

    /* handshake */
    uint8_t  peer_hello_seen;
    uint8_t  hello_sent;
    uint8_t  local_goaway;

    /* identity / auth (copied from config) */
    uint8_t *peer_id; size_t peer_id_len;
    uint8_t *auth;    size_t auth_len;
    uint8_t *nonce;   size_t nonce_len;
    uint32_t weight;

    /* stream-id allocation + monotonic peer-id tracking */
    uint32_t next_local_sid;    /* odd for dialer, even for acceptor       */
    uint32_t max_remote_sid;    /* highest peer-opened id seen             */

    /* stream table (open addressing) */
    mux_stream *tab;
    size_t      tab_cap;        /* power of two                            */
    size_t      tab_count;      /* live streams                            */
    size_t      tab_tombs;      /* tombstones                              */

    /* keepalive */
    uint32_t heartbeat_ms;
    uint32_t keepalive_timeout_ms;
    uint8_t  timer_started;
    uint8_t  ping_outstanding;
    uint64_t ping_due_ms;
    uint64_t ping_sent_ms;
    uint64_t ping_nonce;

    uint32_t max_out_buffer;    /* hard ceiling on out.len (anti-DoS)        */

    outbuf out;
    evq    q;
};

/* Mark/unmark a stream as send-blocked, keeping blocked_count accurate so the
 * connection-window sweep can find blocked streams cheaply. */
static void set_blocked(mux_session *s, mux_stream *st, int blocked) {
    if (blocked && !st->send_blocked) { st->send_blocked = 1; s->blocked_count++; }
    else if (!blocked && st->send_blocked) { st->send_blocked = 0; s->blocked_count--; }
}

/* Hard caps on per-session opaque blobs carried in HELLO (keeps the HELLO
 * crafting buffer bounded and bounds handshake memory). */
#define HELLO_BLOB_MAX 256u

/* ================================================================== */
/* Output buffer                                                      */
/* ================================================================== */

static void raise_fatal(mux_session *s, uint32_t code); /* defined below */

static int ob_reserve(outbuf *o, size_t need, size_t limit) {
    if (o->len + need <= o->cap)
        return 0;
    /* Compact already-sent bytes to the front before growing. */
    if (o->spos > 0) {
        memmove(o->buf, o->buf + o->spos, o->len - o->spos);
        o->len -= o->spos;
        o->spos = 0;
        if (o->len + need <= o->cap)
            return 0;
    }
    /* Refuse to grow past the configured ceiling: this is the anti-DoS /
     * backpressure backstop. The host should have stopped feeding long before. */
    if (limit && o->len + need > limit)
        return MUX_ERR_NOSPACE;
    size_t ncap = o->cap ? o->cap : 4096;
    while (ncap < o->len + need)
        ncap *= 2;
    uint8_t *nb = (uint8_t *)realloc(o->buf, ncap);
    if (!nb)
        return MUX_ERR_NOMEM;
    o->buf = nb;
    o->cap = ncap;
    return 0;
}

/* Craft one frame straight into the output buffer. On overflow of the output
 * ceiling the session is failed (defense in depth) and a negative code returned. */
static int emit(mux_session *s, uint8_t type, uint16_t flags, uint32_t sid,
                const uint8_t *payload, uint32_t plen) {
    if (ob_reserve(&s->out, (size_t)MUX_HEADER_SIZE + plen, s->max_out_buffer) != 0) {
        raise_fatal(s, MUX_CODE_INTERNAL);
        return MUX_ERR_NOSPACE;
    }
    int n = mux_craft(s->out.buf + s->out.len, s->out.cap - s->out.len,
                      type, flags, sid, payload, plen);
    if (n < 0)
        return n;
    s->out.len += (size_t)n;
    return 0;
}

/* ================================================================== */
/* Event queue (growable ring)                                        */
/* ================================================================== */

static int evq_push(evq *q, const mux_event *e) {
    if (q->count == q->cap) {
        size_t ncap = q->cap ? q->cap * 2 : 64;
        mux_event *ne = (mux_event *)malloc(ncap * sizeof *ne);
        if (!ne)
            return MUX_ERR_NOMEM;
        for (size_t i = 0; i < q->count; i++)
            ne[i] = q->ev[(q->head + i) % q->cap];
        free(q->ev);
        q->ev = ne;
        q->cap = ncap;
        q->head = 0;
    }
    q->ev[(q->head + q->count) % q->cap] = *e;
    q->count++;
    return 0;
}

static void ev_simple(mux_session *s, mux_event_type t, uint32_t sid) {
    mux_event e;
    memset(&e, 0, sizeof e);
    e.type = t;
    e.sid  = sid;
    (void)evq_push(&s->q, &e);
}

static void raise_fatal(mux_session *s, uint32_t code) {
    if (s->dead)
        return;
    s->dead = 1;
    mux_event e;
    memset(&e, 0, sizeof e);
    e.type = MUX_EV_FATAL;
    e.u.fatal.code = code;
    (void)evq_push(&s->q, &e);
}

/* ================================================================== */
/* Stream table                                                       */
/* ================================================================== */

static size_t mix_sid(uint32_t sid) {
    uint64_t h = (uint64_t)sid * 0x9e3779b97f4a7c15ull;
    return (size_t)(h >> 32);
}

static mux_stream *st_find(mux_session *s, uint32_t sid) {
    if (s->tab_cap == 0)
        return NULL;
    size_t mask = s->tab_cap - 1;
    size_t i = mix_sid(sid) & mask;
    for (size_t probes = 0; probes <= mask; probes++) {
        mux_stream *e = &s->tab[i];
        if (e->slot == SLOT_EMPTY)
            return NULL;
        if (e->slot == SLOT_USED && e->sid == sid)
            return e;
        i = (i + 1) & mask;
    }
    return NULL;
}

static int st_grow(mux_session *s, size_t want_cap) {
    size_t ncap = s->tab_cap ? s->tab_cap : 64;
    while (ncap < want_cap)
        ncap *= 2;
    mux_stream *nt = (mux_stream *)calloc(ncap, sizeof *nt);
    if (!nt)
        return MUX_ERR_NOMEM;
    size_t nmask = ncap - 1;
    for (size_t i = 0; i < s->tab_cap; i++) {
        mux_stream *e = &s->tab[i];
        if (e->slot != SLOT_USED)
            continue;
        size_t j = mix_sid(e->sid) & nmask;
        while (nt[j].slot == SLOT_USED)
            j = (j + 1) & nmask;
        nt[j] = *e;
    }
    free(s->tab);
    s->tab = nt;
    s->tab_cap = ncap;
    s->tab_tombs = 0;
    return 0;
}

/* Insert a fresh stream record for sid; caller has checked it is absent. */
static mux_stream *st_insert(mux_session *s, uint32_t sid) {
    /* Keep load factor < 3/4 counting tombstones, rehashing as needed. */
    if ((s->tab_count + s->tab_tombs + 1) * 4 >= s->tab_cap * 3) {
        size_t want = (s->tab_count + 1) * 2;
        if (want < 64)
            want = 64;
        if (st_grow(s, want) != 0)
            return NULL;
    }
    size_t mask = s->tab_cap - 1;
    size_t i = mix_sid(sid) & mask;
    size_t first_tomb = (size_t)-1;
    for (size_t probes = 0; probes <= mask; probes++) {
        mux_stream *e = &s->tab[i];
        if (e->slot == SLOT_EMPTY) {
            mux_stream *dst = (first_tomb != (size_t)-1) ? &s->tab[first_tomb] : e;
            if (first_tomb != (size_t)-1)
                s->tab_tombs--;
            memset(dst, 0, sizeof *dst);
            dst->sid = sid;
            dst->slot = SLOT_USED;
            s->tab_count++;
            return dst;
        }
        if (e->slot == SLOT_TOMB && first_tomb == (size_t)-1)
            first_tomb = i;
        i = (i + 1) & mask;
    }
    return NULL; /* table full (shouldn't happen given the grow above) */
}

static void st_remove(mux_session *s, mux_stream *e) {
    if (e->send_blocked) {                   /* keep blocked_count exact */
        e->send_blocked = 0;
        s->blocked_count--;
    }
    e->slot = SLOT_TOMB;
    s->tab_count--;
    s->tab_tombs++;
}

/* ================================================================== */
/* Construction / teardown                                            */
/* ================================================================== */

static int send_hello(mux_session *s, int ack); /* defined below */

static uint8_t *dup_blob(const uint8_t *p, size_t n) {
    if (!p || n == 0)
        return NULL;
    uint8_t *d = (uint8_t *)malloc(n);
    if (d)
        memcpy(d, p, n);
    return d;
}

static uint32_t nz(uint32_t v, uint32_t dflt) { return v ? v : dflt; }

mux_session *mux_session_new(const mux_config *cfg, mux_role role) {
    if (!cfg)
        return NULL;
    if (cfg->peer_id_len > HELLO_BLOB_MAX || cfg->auth_len > HELLO_BLOB_MAX ||
        cfg->nonce_len  > HELLO_BLOB_MAX)
        return NULL;

    mux_session *s = (mux_session *)calloc(1, sizeof *s);
    if (!s)
        return NULL;

    s->role            = role;
    s->init_window     = nz(cfg->init_window,    MUX_DEFAULT_INIT_WINDOW);
    s->session_window  = nz(cfg->session_window, MUX_DEFAULT_SESSION_WINDOW);
    s->max_streams     = nz(cfg->max_streams,    MUX_DEFAULT_MAX_STREAMS);
    s->heartbeat_ms    = cfg->heartbeat_ms; /* 0 legitimately disables it */
    s->keepalive_timeout_ms = cfg->keepalive_timeout_ms
        ? cfg->keepalive_timeout_ms
        : (s->heartbeat_ms ? s->heartbeat_ms * 3u : 0u);
    s->weight          = cfg->weight;
    s->max_out_buffer  = nz(cfg->max_out_buffer, MUX_DEFAULT_MAX_OUT_BUFFER);

    /* Until the peer's HELLO arrives, assume protocol defaults so a stream
     * opened immediately after the handshake has a sane initial send window. */
    s->peer_init_window = MUX_DEFAULT_INIT_WINDOW;
    s->peer_max_streams = MUX_DEFAULT_MAX_STREAMS;
    s->sess_send_win    = (int64_t)MUX_DEFAULT_SESSION_WINDOW;
    s->sess_recv_win    = (int64_t)s->session_window;

    s->next_local_sid = (role == MUX_DIALER) ? 1u : 2u;

    if (cfg->peer_id_len) { s->peer_id = dup_blob(cfg->peer_id, cfg->peer_id_len);
                            if (!s->peer_id) goto fail; s->peer_id_len = cfg->peer_id_len; }
    if (cfg->auth_len)    { s->auth = dup_blob(cfg->auth, cfg->auth_len);
                            if (!s->auth) goto fail; s->auth_len = cfg->auth_len; }
    if (cfg->nonce_len)   { s->nonce = dup_blob(cfg->nonce, cfg->nonce_len);
                            if (!s->nonce) goto fail; s->nonce_len = cfg->nonce_len; }

    size_t want = (size_t)s->max_streams * 2;
    if (want < 64) want = 64;
    if (st_grow(s, want) != 0)
        goto fail;

    /* The dialer greets immediately; its HELLO sits in the output buffer for
     * the host's first flush. The acceptor replies only after seeing it. */
    if (role == MUX_DIALER && send_hello(s, 0) != 0)
        goto fail;

    return s;
fail:
    mux_session_free(s);
    return NULL;
}

void mux_session_free(mux_session *s) {
    if (!s)
        return;
    free(s->tab);
    free(s->out.buf);
    free(s->q.ev);
    free(s->peer_id);
    free(s->auth);
    free(s->nonce);
    free(s);
}

/* ================================================================== */
/* Handshake                                                          */
/* ================================================================== */

static int put_u32_tlv(uint8_t *buf, size_t cap, size_t off, uint16_t t, uint32_t v) {
    uint8_t b[4];
    be_put32(b, v);
    return mux_tlv_put(buf, cap, off, t, b, 4);
}

static int send_hello(mux_session *s, int ack) {
    uint8_t blob[1024];
    size_t off = 0;
    int r;

#define TLV_U32(T, V) do { r = put_u32_tlv(blob, sizeof blob, off, (T), (V)); \
                           if (r < 0) return r; off = (size_t)r; } while (0)
#define TLV_BLOB(T, P, N) do { if ((N)) { \
        r = mux_tlv_put(blob, sizeof blob, off, (T), (P), (uint16_t)(N)); \
        if (r < 0) return r; off = (size_t)r; } } while (0)

    TLV_U32(MUX_TLV_WEIGHT,         s->weight);
    TLV_U32(MUX_TLV_MAX_STREAMS,    s->max_streams);
    TLV_U32(MUX_TLV_INIT_WINDOW,    s->init_window);
    TLV_U32(MUX_TLV_SESSION_WINDOW, s->session_window);
    TLV_U32(MUX_TLV_HEARTBEAT_MS,   s->heartbeat_ms);
    TLV_BLOB(MUX_TLV_PEER_ID, s->peer_id, s->peer_id_len);
    TLV_BLOB(MUX_TLV_AUTH,    s->auth,    s->auth_len);
    TLV_BLOB(MUX_TLV_NONCE,   s->nonce,   s->nonce_len);
#undef TLV_U32
#undef TLV_BLOB

    int e = emit(s, ack ? MUX_T_HELLO_ACK : MUX_T_HELLO, 0,
                 MUX_SID_CONTROL, blob, (uint32_t)off);
    if (e == 0)
        s->hello_sent = 1;
    return e;
}

/* ================================================================== */
/* Flow-control crediting (receive side)                              */
/* ================================================================== */

/* Emit `pending` bytes of credit on `sid` as one or more WINDOW_UPDATE frames,
 * advancing `*win` by exactly the amount placed on the wire. Splitting into
 * <= UINT32_MAX chunks keeps the wire value and the local window in lockstep
 * even when a single huge consume accumulates more than 4 GiB of credit. */
static void credit_emit(mux_session *s, uint32_t sid, int64_t *win, int64_t *pending) {
    while (*pending > 0) {
        uint32_t chunk = (*pending > (int64_t)0xFFFFFFFF)
                       ? 0xFFFFFFFFu : (uint32_t)*pending;
        uint8_t b[4];
        be_put32(b, chunk);
        if (emit(s, MUX_T_WINDOW_UPDATE, 0, sid, b, 4) != 0)
            return;                 /* out buffer full / fatal: leave the rest pending */
        *win     += (int64_t)chunk;
        *pending -= (int64_t)chunk;
    }
}

static void credit_stream(mux_session *s, mux_stream *st) {
    if (st->recv_pending <= 0)
        return;
    /* Refill at the half-window watermark to batch WINDOW_UPDATE frames. */
    if (st->recv_pending * 2 < (int64_t)s->init_window)
        return;
    credit_emit(s, st->sid, &st->recv_win, &st->recv_pending);
}

static void credit_session(mux_session *s) {
    if (s->sess_recv_pending <= 0)
        return;
    if (s->sess_recv_pending * 2 < (int64_t)s->session_window)
        return;
    credit_emit(s, MUX_SID_CONTROL, &s->sess_recv_win, &s->sess_recv_pending);
}

/* ================================================================== */
/* Frame handlers                                                     */
/* ================================================================== */

/* Free a stream and account for direction-specific teardown. */
static void close_stream(mux_session *s, mux_stream *st) {
    st_remove(s, st);
}

static void on_data(mux_session *s, const mux_frame_t *f) {
    uint16_t fl = f->flags;

    if (fl & MUX_F_SYN) {
        /* New inbound stream. Peer must have greeted first. */
        if (!s->peer_hello_seen) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
        /* Parity: peer uses the opposite parity to ours. */
        uint32_t want_odd = (s->role == MUX_DIALER) ? 0u : 1u; /* peer's parity */
        if ((f->sid & 1u) != want_odd) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
        if (f->sid == MUX_SID_CONTROL) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
        if (st_find(s, f->sid)) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
        /* Stream ids must increase monotonically; a reused/old id is illegal. */
        if (f->sid <= s->max_remote_sid) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
        /* SYN metadata is bounded independently of the data windows. */
        if (f->len > MUX_MAX_META) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }

        /* Refuse (not fatal) if we're at our inbound cap or draining. */
        if (s->tab_count >= s->max_streams || s->local_goaway) {
            uint8_t code[4]; be_put32(code, MUX_CODE_REFUSED);
            (void)emit(s, MUX_T_DATA, MUX_F_RST, f->sid, code, 4);
            s->max_remote_sid = f->sid;
            return;
        }

        mux_stream *st = st_insert(s, f->sid);
        if (!st) { raise_fatal(s, MUX_CODE_INTERNAL); return; }
        st->life = LIFE_OPEN;
        st->send_win = (int64_t)s->peer_init_window;
        st->recv_win = (int64_t)s->init_window;
        s->max_remote_sid = f->sid;

        mux_event e;
        memset(&e, 0, sizeof e);
        e.type = MUX_EV_STREAM_OPENED;
        e.sid  = f->sid;
        e.u.opened.meta = f->payload;       /* SYN payload = metadata TLV */
        e.u.opened.meta_len = f->len;
        (void)evq_push(&s->q, &e);

        if (fl & MUX_F_RST) { ev_simple(s, MUX_EV_STREAM_RESET, f->sid); close_stream(s, st); return; }
        if (fl & MUX_F_FIN) {
            st->life = LIFE_HCL_REMOTE;
            ev_simple(s, MUX_EV_STREAM_CLOSED, f->sid);
        }
        return;
    }

    /* Stream id 0 is reserved for control frames; DATA on it is illegal. */
    if (f->sid == MUX_SID_CONTROL) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }

    /* Non-SYN DATA: must reference a live stream. A frame for an unknown id is
     * almost always one in flight when we closed the stream — drop it silently
     * rather than answering with an RST, which would amplify into a storm and
     * mis-label benign late frames as errors. The bytes self-limit: we never
     * credit them, so the peer's own send window drains and it stalls. */
    mux_stream *st = st_find(s, f->sid);
    if (!st)
        return;

    if (fl & MUX_F_RST) {
        mux_event e; memset(&e, 0, sizeof e);
        e.type = MUX_EV_STREAM_RESET;
        e.sid  = f->sid;
        e.u.reset.code = (f->len >= 4) ? be_get32(f->payload) : MUX_CODE_NO_ERROR;
        (void)evq_push(&s->q, &e);
        close_stream(s, st);
        return;
    }

    if (f->len > 0) {
        if (st->life == LIFE_HCL_REMOTE) {  /* data after the peer's FIN */
            uint8_t code[4]; be_put32(code, MUX_CODE_PROTOCOL);
            (void)emit(s, MUX_T_DATA, MUX_F_RST, f->sid, code, 4);
            ev_simple(s, MUX_EV_STREAM_RESET, f->sid);
            close_stream(s, st);
            return;
        }
        /* Connection-window overrun is the peer ignoring a hard cap: fatal.
         * Stream-window overrun is localized: reset just that stream. */
        if ((int64_t)f->len > s->sess_recv_win) { raise_fatal(s, MUX_CODE_FLOW_CONTROL); return; }
        if ((int64_t)f->len > st->recv_win) {
            uint8_t code[4]; be_put32(code, MUX_CODE_FLOW_CONTROL);
            (void)emit(s, MUX_T_DATA, MUX_F_RST, f->sid, code, 4);
            ev_simple(s, MUX_EV_STREAM_RESET, f->sid);
            close_stream(s, st);
            return;
        }
        st->recv_win     -= (int64_t)f->len;
        s->sess_recv_win -= (int64_t)f->len;

        mux_event e; memset(&e, 0, sizeof e);
        e.type = MUX_EV_STREAM_DATA;
        e.sid  = f->sid;
        e.u.data.data = f->payload;
        e.u.data.data_len = f->len;
        (void)evq_push(&s->q, &e);
    }

    if (fl & MUX_F_FIN) {
        ev_simple(s, MUX_EV_STREAM_CLOSED, f->sid);
        if (st->life == LIFE_HCL_LOCAL)
            close_stream(s, st);            /* both sides done */
        else
            st->life = LIFE_HCL_REMOTE;
    }
}

static void on_window_update(mux_session *s, const mux_frame_t *f) {
    if (f->len != 4) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
    uint32_t credit = be_get32(f->payload);

    if (f->sid == MUX_SID_CONTROL) {
        int was_blocked = s->sess_send_win <= 0;
        s->sess_send_win += (int64_t)credit;
        if (s->sess_send_win > ((int64_t)1 << 48)) { raise_fatal(s, MUX_CODE_FLOW_CONTROL); return; }
        /* The connection window just reopened: a stream can be blocked solely
         * on it while its own window is healthy, so sweep every blocked stream
         * and wake the ones that now have room on BOTH windows. Without this the
         * stream deadlocks at window 0 (a per-stream WU never comes, because the
         * stuck bytes are never sent and thus never consumed/credited). */
        if (was_blocked && s->sess_send_win > 0 && s->blocked_count > 0) {
            for (size_t i = 0; i < s->tab_cap; i++) {
                mux_stream *st = &s->tab[i];
                if (st->slot == SLOT_USED && st->send_blocked && st->send_win > 0) {
                    set_blocked(s, st, 0);
                    ev_simple(s, MUX_EV_WRITABLE, st->sid);
                }
            }
        }
        return;
    }

    mux_stream *st = st_find(s, f->sid);
    if (!st)
        return;                             /* closed stream: ignore */
    st->send_win += (int64_t)credit;
    if (st->send_win > ((int64_t)1 << 48)) { raise_fatal(s, MUX_CODE_FLOW_CONTROL); return; }
    /* Wake the stream only when BOTH windows allow progress; if it is blocked
     * on the connection window the sid-0 sweep above will wake it instead. */
    if (st->send_blocked && st->send_win > 0 && s->sess_send_win > 0) {
        set_blocked(s, st, 0);
        ev_simple(s, MUX_EV_WRITABLE, f->sid);
    }
}

static void on_ping(mux_session *s, const mux_frame_t *f) {
    /* PING is a fixed 8-byte control frame. Enforcing both the id and the
     * length stops a peer from using oversized echoes to force unbounded
     * output-buffer growth (echo amplification). */
    if (f->sid != MUX_SID_CONTROL || f->len != 8) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
    if (f->flags & MUX_F_ACK) {
        s->ping_outstanding = 0;            /* echo of our keepalive: peer alive */
        return;
    }
    (void)emit(s, MUX_T_PING, MUX_F_ACK, MUX_SID_CONTROL, f->payload, 8);
}

static void on_goaway(mux_session *s, const mux_frame_t *f) {
    if (f->sid != MUX_SID_CONTROL) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
    if (f->len < 8) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
    mux_event e; memset(&e, 0, sizeof e);
    e.type = MUX_EV_GOAWAY;
    e.u.goaway.reason   = be_get32(f->payload);
    e.u.goaway.last_sid = be_get32(f->payload + 4);
    (void)evq_push(&s->q, &e);
}

static void on_capacity(mux_session *s, const mux_frame_t *f) {
    if (f->sid != MUX_SID_CONTROL) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
    if (f->len != 4) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
    mux_event e; memset(&e, 0, sizeof e);
    e.type = MUX_EV_CAPACITY;
    e.u.capacity.weight = be_get32(f->payload);
    (void)evq_push(&s->q, &e);
}

static void on_hello(mux_session *s, const mux_frame_t *f, int ack) {
    if (f->sid != MUX_SID_CONTROL) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
    if (s->peer_hello_seen)        { raise_fatal(s, MUX_CODE_PROTOCOL); return; }

    mux_event e; memset(&e, 0, sizeof e);
    e.type = MUX_EV_PEER_HELLO;

    size_t cursor = 0;
    uint16_t t, vlen; const uint8_t *val;
    for (;;) {
        int g = mux_tlv_next(f->payload, f->len, &cursor, &t, &val, &vlen);
        if (g == 0) break;
        if (g < 0) { raise_fatal(s, MUX_CODE_PROTOCOL); return; }
        switch (t) {
        case MUX_TLV_WEIGHT:         if (vlen == 4) e.u.hello.weight = be_get32(val); break;
        case MUX_TLV_MAX_STREAMS:    if (vlen == 4) { s->peer_max_streams = be_get32(val);
                                                      e.u.hello.max_streams = s->peer_max_streams; } break;
        case MUX_TLV_INIT_WINDOW:    if (vlen == 4) { s->peer_init_window = be_get32(val);
                                                      e.u.hello.init_window = s->peer_init_window; } break;
        case MUX_TLV_SESSION_WINDOW: if (vlen == 4) s->sess_send_win = (int64_t)be_get32(val); break;
        case MUX_TLV_PEER_ID:        e.u.hello.peer_id = val; e.u.hello.peer_id_len = vlen; break;
        case MUX_TLV_AUTH:           e.u.hello.auth = val;    e.u.hello.auth_len = vlen;    break;
        case MUX_TLV_NONCE:          e.u.hello.nonce = val;   e.u.hello.nonce_len = vlen;   break;
        default: break;             /* forward-compatible: ignore unknown */
        }
    }

    s->peer_hello_seen = 1;
    (void)evq_push(&s->q, &e);

    /* Acceptor greets back once, in response to the dialer's HELLO. */
    if (!ack && s->role == MUX_ACCEPTOR && !s->hello_sent)
        (void)send_hello(s, 1);
}

static void process_frame(mux_session *s, const mux_frame_t *f) {
    /* Before the peer greets, only HELLO/HELLO_ACK are legal. */
    if (!s->peer_hello_seen && f->type != MUX_T_HELLO && f->type != MUX_T_HELLO_ACK) {
        raise_fatal(s, MUX_CODE_PROTOCOL);
        return;
    }
    switch (f->type) {
    case MUX_T_DATA:          on_data(s, f); break;
    case MUX_T_WINDOW_UPDATE: on_window_update(s, f); break;
    case MUX_T_PING:          on_ping(s, f); break;
    case MUX_T_GOAWAY:        on_goaway(s, f); break;
    case MUX_T_HELLO:         on_hello(s, f, 0); break;
    case MUX_T_HELLO_ACK:     on_hello(s, f, 1); break;
    case MUX_T_CAPACITY:      on_capacity(s, f); break;
    default:                  raise_fatal(s, MUX_CODE_PROTOCOL); break;
    }
}

/* ================================================================== */
/* Public API                                                         */
/* ================================================================== */

int64_t mux_recv(mux_session *s, const uint8_t *buf, size_t len) {
    if (!s || (!buf && len))
        return MUX_ERR_PARAM;
    if (s->dead)
        return MUX_ERR_STATE;

    size_t cursor = 0;
    while (cursor < len) {
        /* Soft-cap the event queue: stop consuming so the host drains events
         * (bounding queue memory). The unconsumed tail is re-fed next call. */
        if (s->q.count >= MUX_EVENT_QUEUE_SOFT_CAP)
            break;

        mux_frame_t f;
        size_t consumed = 0;
        int r = mux_parse(buf + cursor, len - cursor, &f, &consumed);
        if (r == MUX_ERR_SHORT)
            break;                          /* wait for more bytes */
        if (r != MUX_OK) {                  /* framing-level violation */
            raise_fatal(s, MUX_CODE_PROTOCOL);
            break;                          /* exclude the offending frame */
        }
        process_frame(s, &f);
        if (s->dead)
            break;                          /* semantic fatal: also exclude it */
        cursor += consumed;
    }
    return (int64_t)cursor;
}

int64_t mux_open(mux_session *s, const uint8_t *meta, size_t meta_len) {
    if (!s)                       return MUX_ERR_PARAM;
    if (s->dead)                  return MUX_ERR_STATE;
    if (!s->peer_hello_seen)      return MUX_ERR_STATE;   /* need peer window */
    if (s->local_goaway)          return MUX_ERR_STATE;
    if (meta_len > MUX_MAX_META)  return MUX_ERR_PARAM;
    if (s->tab_count >= s->peer_max_streams) return MUX_ERR_NOMEM;

    uint32_t sid = s->next_local_sid;
    if (sid == MUX_SID_CONTROL)   return MUX_ERR_STATE;   /* id space wrapped to 0: exhausted */
    s->next_local_sid += 2u;

    mux_stream *st = st_insert(s, sid);
    if (!st)                      return MUX_ERR_NOMEM;
    st->life = LIFE_OPEN;
    st->send_win = (int64_t)s->peer_init_window;
    st->recv_win = (int64_t)s->init_window;

    if (emit(s, MUX_T_DATA, MUX_F_SYN, sid,
             meta_len ? meta : NULL, (uint32_t)meta_len) != 0) {
        st_remove(s, st);
        return MUX_ERR_NOMEM;
    }
    return (int64_t)sid;
}

int64_t mux_write(mux_session *s, uint32_t sid, const uint8_t *p, size_t n) {
    if (!s || (!p && n))          return MUX_ERR_PARAM;
    if (s->dead)                  return MUX_ERR_STATE;
    mux_stream *st = st_find(s, sid);
    if (!st)                      return MUX_ERR_NOSTREAM;
    if (st->life == LIFE_HCL_LOCAL) return MUX_ERR_STATE; /* we already FIN'd */

    int64_t room = st->send_win;
    if (s->sess_send_win < room)
        room = s->sess_send_win;
    if (room <= 0) {
        set_blocked(s, st, 1);          /* blocked on stream and/or session win */
        return 0;
    }
    size_t want = n;
    if ((int64_t)want > room)
        want = (size_t)room;

    size_t sent = 0;
    while (sent < want) {
        size_t chunk = want - sent;
        if (chunk > MUX_MAX_DATA_FRAME)
            chunk = MUX_MAX_DATA_FRAME;
        if (emit(s, MUX_T_DATA, 0, sid, p + sent, (uint32_t)chunk) != 0)
            break;                          /* out buffer full / fatal: stop early */
        sent += chunk;
    }
    st->send_win     -= (int64_t)sent;
    s->sess_send_win -= (int64_t)sent;
    /* Couldn't place everything: mark blocked so a later WINDOW_UPDATE wakes us. */
    if (sent < n && (st->send_win <= 0 || s->sess_send_win <= 0))
        set_blocked(s, st, 1);
    return (int64_t)sent;
}

int mux_close(mux_session *s, uint32_t sid) {
    if (!s)          return MUX_ERR_PARAM;
    if (s->dead)     return MUX_ERR_STATE;
    mux_stream *st = st_find(s, sid);
    if (!st)         return MUX_ERR_NOSTREAM;
    if (st->life == LIFE_HCL_LOCAL)
        return MUX_OK;                      /* already half-closed locally */
    if (emit(s, MUX_T_DATA, MUX_F_FIN, sid, NULL, 0) != 0)
        return MUX_ERR_NOMEM;
    if (st->life == LIFE_HCL_REMOTE)
        close_stream(s, st);                /* both directions done */
    else
        st->life = LIFE_HCL_LOCAL;
    return MUX_OK;
}

int mux_reset(mux_session *s, uint32_t sid, uint32_t code) {
    if (!s)      return MUX_ERR_PARAM;
    if (s->dead) return MUX_ERR_STATE;
    mux_stream *st = st_find(s, sid);
    if (!st)     return MUX_OK;             /* already gone */
    uint8_t b[4]; be_put32(b, code);
    (void)emit(s, MUX_T_DATA, MUX_F_RST, sid, b, 4);
    close_stream(s, st);
    return MUX_OK;
}

int mux_consume(mux_session *s, uint32_t sid, size_t n) {
    if (!s)      return MUX_ERR_PARAM;
    if (s->dead) return MUX_ERR_STATE;
    if (n == 0)  return MUX_OK;
    s->sess_recv_pending += (int64_t)n;
    credit_session(s);
    mux_stream *st = st_find(s, sid);
    if (st) {
        st->recv_pending += (int64_t)n;
        credit_stream(s, st);
    }
    return MUX_OK;
}

int mux_send_capacity(mux_session *s, uint32_t weight) {
    if (!s)      return MUX_ERR_PARAM;
    if (s->dead) return MUX_ERR_STATE;
    uint8_t b[4]; be_put32(b, weight);
    return emit(s, MUX_T_CAPACITY, 0, MUX_SID_CONTROL, b, 4);
}

int mux_goaway(mux_session *s, uint32_t reason) {
    if (!s)      return MUX_ERR_PARAM;
    if (s->dead) return MUX_ERR_STATE;
    s->local_goaway = 1;
    uint8_t b[8];
    be_put32(b, reason);
    be_put32(b + 4, s->max_remote_sid);
    return emit(s, MUX_T_GOAWAY, 0, MUX_SID_CONTROL, b, 8);
}

uint64_t mux_on_timer(mux_session *s, uint64_t now_ms) {
    if (!s || s->dead || s->heartbeat_ms == 0)
        return UINT64_MAX;

    if (!s->timer_started) {
        s->timer_started = 1;
        s->ping_due_ms = now_ms + s->heartbeat_ms;
        return s->ping_due_ms;
    }

    /* Dead peer: keepalive went unanswered past the timeout. */
    if (s->ping_outstanding && s->keepalive_timeout_ms &&
        now_ms - s->ping_sent_ms >= s->keepalive_timeout_ms) {
        raise_fatal(s, MUX_CODE_INTERNAL);
        return UINT64_MAX;
    }

    if (now_ms >= s->ping_due_ms) {
        uint8_t b[8];
        be_put32(b, (uint32_t)(s->ping_nonce >> 32));
        be_put32(b + 4, (uint32_t)s->ping_nonce);
        if (emit(s, MUX_T_PING, 0, MUX_SID_CONTROL, b, 8) == 0) {
            s->ping_outstanding = 1;
            s->ping_sent_ms = now_ms;
            s->ping_nonce++;
            s->ping_due_ms = now_ms + s->heartbeat_ms;
        }
    }

    uint64_t next = s->ping_due_ms;
    if (s->ping_outstanding && s->keepalive_timeout_ms) {
        uint64_t deadline = s->ping_sent_ms + s->keepalive_timeout_ms;
        if (deadline < next)
            next = deadline;
    }
    return next;
}

const uint8_t *mux_send_buf(mux_session *s, size_t *len) {
    if (!s || !len) { if (len) *len = 0; return NULL; }
    *len = s->out.len - s->out.spos;
    return s->out.buf + s->out.spos;
}

size_t mux_out_pending(mux_session *s) {
    return s ? s->out.len - s->out.spos : 0;
}

void mux_send_advance(mux_session *s, size_t n) {
    if (!s)
        return;
    size_t avail = s->out.len - s->out.spos;
    if (n > avail)
        n = avail;
    s->out.spos += n;
    if (s->out.spos == s->out.len) {        /* fully drained: reuse from 0 */
        s->out.spos = 0;
        s->out.len = 0;
    }
}

int mux_next_event(mux_session *s, mux_event *ev) {
    if (!s || !ev || s->q.count == 0)
        return 0;
    *ev = s->q.ev[s->q.head];
    s->q.head = (s->q.head + 1) % s->q.cap;
    s->q.count--;
    return 1;
}
