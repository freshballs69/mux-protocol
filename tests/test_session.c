/* Deterministic state-machine tests for mux_session.
 *
 * The core is sans-io, so we test it with zero sockets and zero sleeps:
 * two sessions are wired mouth-to-ear through an in-memory pump, and we
 * assert on the events each side emits and (implicitly) the bytes that
 * crossed the wire. Every test is reproducible to the byte.
 */
#include "mux.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)
#define CHECK_EQ(a,b) do { long long _a=(long long)(a),_b=(long long)(b); \
    if (_a!=_b){ fprintf(stderr,"FAIL %s:%d  %s(%lld) != %s(%lld)\n", \
    __FILE__,__LINE__,#a,_a,#b,_b); g_fail++; } } while (0)

/* ---- event collector ------------------------------------------------ */

typedef struct {
    mux_event_type type;
    uint32_t sid;
    uint32_t code;          /* reset/fatal/goaway-reason */
    uint32_t weight, max_streams, init_window; /* hello/capacity */
    uint8_t  blob[256];     /* copied meta/data (first bytes) */
    size_t   blob_len;
    size_t   data_total;    /* running per-event data length (for sums) */
} logev;

typedef struct {
    logev   ev[2048];
    size_t  n;
    /* aggregates */
    size_t  data_bytes;     /* total STREAM_DATA bytes seen */
    int     fatal;
} evlog;

static void drain(mux_session *s, evlog *L) {
    mux_event e;
    while (mux_next_event(s, &e)) {
        if (L->n >= sizeof L->ev / sizeof L->ev[0]) return;
        logev *r = &L->ev[L->n++];
        memset(r, 0, sizeof *r);
        r->type = e.type;
        r->sid  = e.sid;
        switch (e.type) {
        case MUX_EV_STREAM_OPENED:
            r->blob_len = e.u.opened.meta_len < sizeof r->blob ? e.u.opened.meta_len : sizeof r->blob;
            if (r->blob_len) memcpy(r->blob, e.u.opened.meta, r->blob_len);
            break;
        case MUX_EV_STREAM_DATA:
            r->data_total = e.u.data.data_len;
            L->data_bytes += e.u.data.data_len;
            r->blob_len = e.u.data.data_len < sizeof r->blob ? e.u.data.data_len : sizeof r->blob;
            if (r->blob_len) memcpy(r->blob, e.u.data.data, r->blob_len);
            break;
        case MUX_EV_STREAM_RESET: r->code = e.u.reset.code; break;
        case MUX_EV_PEER_HELLO:
            r->weight = e.u.hello.weight;
            r->max_streams = e.u.hello.max_streams;
            r->init_window = e.u.hello.init_window;
            break;
        case MUX_EV_CAPACITY: r->weight = e.u.capacity.weight; break;
        case MUX_EV_GOAWAY:   r->code = e.u.goaway.reason; r->sid = e.u.goaway.last_sid; break;
        case MUX_EV_FATAL:    r->code = e.u.fatal.code; L->fatal = 1; break;
        default: break;
        }
    }
}

static int count_type(const evlog *L, mux_event_type t) {
    int c = 0;
    for (size_t i = 0; i < L->n; i++) if (L->ev[i].type == t) c++;
    return c;
}
static const logev *find_type(const evlog *L, mux_event_type t) {
    for (size_t i = 0; i < L->n; i++) if (L->ev[i].type == t) return &L->ev[i];
    return NULL;
}

/* ---- the pump ------------------------------------------------------- */
/* Move bytes one way: src.out -> dst.recv, advancing src and draining dst. */
static size_t move(mux_session *src, mux_session *dst, evlog *dstlog) {
    size_t len = 0;
    const uint8_t *buf = mux_send_buf(src, &len);
    if (len == 0) return 0;
    int consumed = mux_recv(dst, buf, len);
    if (consumed > 0) mux_send_advance(src, (size_t)consumed);
    drain(dst, dstlog);
    return consumed > 0 ? (size_t)consumed : 0;
}

/* Run both directions until the wire goes quiet. */
static void pump(mux_session *a, mux_session *b, evlog *la, evlog *lb) {
    for (int round = 0; round < 10000; round++) {
        size_t moved = 0;
        moved += move(a, b, lb);
        moved += move(b, a, la);
        if (moved == 0) break;
    }
}

/* ---- fixtures ------------------------------------------------------- */

static mux_config cfg_with(uint32_t iw, uint32_t sw, uint32_t ms, uint32_t hb) {
    mux_config c; memset(&c, 0, sizeof c);
    c.init_window = iw; c.session_window = sw; c.max_streams = ms;
    c.heartbeat_ms = hb; c.weight = 8;
    return c;
}

/* ---- tests ---------------------------------------------------------- */

static void test_handshake(void) {
    mux_config cd = cfg_with(0,0,0,0); cd.weight = 8;
    mux_config ca = cfg_with(0,0,0,0); ca.weight = 16;
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    CHECK(d && a);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);

    /* Each side learns the other's HELLO exactly once. */
    CHECK_EQ(count_type(&ld, MUX_EV_PEER_HELLO), 1);
    CHECK_EQ(count_type(&la, MUX_EV_PEER_HELLO), 1);
    const logev *dh = find_type(&ld, MUX_EV_PEER_HELLO); /* dialer saw acceptor */
    const logev *ah = find_type(&la, MUX_EV_PEER_HELLO); /* acceptor saw dialer */
    CHECK(dh && ah);
    CHECK_EQ(dh->weight, 16);
    CHECK_EQ(ah->weight, 8);
    CHECK(!ld.fatal && !la.fatal);
    mux_session_free(d); mux_session_free(a);
}

static void test_open_data_close(void) {
    mux_config cd = cfg_with(0,0,0,0), ca = cfg_with(0,0,0,0);
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);

    /* dialer opens a stream carrying metadata */
    const char *meta = "src=1.2.3.4:5555";
    int64_t sid = mux_open(d, (const uint8_t *)meta, strlen(meta));
    CHECK(sid == 1); /* dialer uses odd ids starting at 1 */
    pump(d, a, &ld, &la);

    const logev *op = find_type(&la, MUX_EV_STREAM_OPENED);
    CHECK(op != NULL);
    if (op) {
        CHECK_EQ(op->sid, 1);
        CHECK_EQ(op->blob_len, strlen(meta));
        CHECK(memcmp(op->blob, meta, op->blob_len) == 0);
    }

    /* data dialer -> acceptor */
    const char *msg = "hello world";
    int64_t w = mux_write(d, (uint32_t)sid, (const uint8_t *)msg, strlen(msg));
    CHECK_EQ(w, (int64_t)strlen(msg));
    pump(d, a, &ld, &la);
    CHECK_EQ(la.data_bytes, strlen(msg));
    const logev *dat = find_type(&la, MUX_EV_STREAM_DATA);
    CHECK(dat && memcmp(dat->blob, msg, strlen(msg)) == 0);
    /* acceptor consumes -> should credit back (no assert on WU bytes here) */
    mux_consume(a, (uint32_t)sid, strlen(msg));
    pump(d, a, &ld, &la);

    /* half-close from dialer; acceptor still open the other way */
    CHECK_EQ(mux_close(d, (uint32_t)sid), MUX_OK);
    pump(d, a, &ld, &la);
    CHECK_EQ(count_type(&la, MUX_EV_STREAM_CLOSED), 1);

    /* acceptor can still send back before its own FIN */
    int64_t aw = mux_write(a, (uint32_t)sid, (const uint8_t *)"ack", 3);
    CHECK_EQ(aw, 3);
    pump(d, a, &ld, &la);
    CHECK_EQ(ld.data_bytes, 3);

    /* acceptor closes -> stream fully torn down on both ends */
    CHECK_EQ(mux_close(a, (uint32_t)sid), MUX_OK);
    pump(d, a, &ld, &la);
    CHECK_EQ(count_type(&ld, MUX_EV_STREAM_CLOSED), 1);

    /* writing to the now-closed stream fails */
    CHECK_EQ(mux_write(d, (uint32_t)sid, (const uint8_t *)"x", 1), MUX_ERR_NOSTREAM);
    CHECK(!ld.fatal && !la.fatal);
    mux_session_free(d); mux_session_free(a);
}

static void test_reset(void) {
    mux_config cd = cfg_with(0,0,0,0), ca = cfg_with(0,0,0,0);
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);
    int64_t sid = mux_open(d, NULL, 0);
    pump(d, a, &ld, &la);
    CHECK_EQ(mux_reset(d, (uint32_t)sid, MUX_CODE_INTERNAL), MUX_OK);
    pump(d, a, &ld, &la);
    const logev *rst = find_type(&la, MUX_EV_STREAM_RESET);
    CHECK(rst != NULL);
    if (rst) CHECK_EQ(rst->code, MUX_CODE_INTERNAL);
    /* both sides have freed it: a second write is NOSTREAM */
    CHECK_EQ(mux_write(d, (uint32_t)sid, (const uint8_t *)"x", 1), MUX_ERR_NOSTREAM);
    mux_session_free(d); mux_session_free(a);
}

/* Per-stream flow control: small window blocks, consume reopens it. */
static void test_flow_control_stream(void) {
    /* init_window 16 so the receiver only admits 16 bytes before crediting */
    mux_config cd = cfg_with(16, 1<<20, 0, 0);
    mux_config ca = cfg_with(16, 1<<20, 0, 0);
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);
    int64_t sid = mux_open(d, NULL, 0);
    pump(d, a, &ld, &la);

    /* acceptor advertised init_window 16, so dialer's send window is 16 */
    uint8_t big[64];
    memset(big, 'A', sizeof big);
    int64_t w = mux_write(d, (uint32_t)sid, big, sizeof big);
    CHECK_EQ(w, 16);                 /* clamped to the peer's window */
    pump(d, a, &ld, &la);
    CHECK_EQ(la.data_bytes, 16);

    /* window is now 0: further writes block */
    int64_t w2 = mux_write(d, (uint32_t)sid, big, sizeof big);
    CHECK_EQ(w2, 0);

    /* acceptor consumes 16 -> credits a full window back -> dialer WRITABLE */
    mux_consume(a, (uint32_t)sid, 16);
    pump(d, a, &ld, &la);
    CHECK(count_type(&ld, MUX_EV_WRITABLE) >= 1);

    /* now another 16 bytes flow */
    int64_t w3 = mux_write(d, (uint32_t)sid, big, sizeof big);
    CHECK_EQ(w3, 16);
    pump(d, a, &ld, &la);
    CHECK_EQ(la.data_bytes, 32);
    CHECK(!ld.fatal && !la.fatal);
    mux_session_free(d); mux_session_free(a);
}

/* Connection-level cap: independent streams cannot collectively exceed the
 * session window even though each has plenty of per-stream window. */
static void test_flow_control_session(void) {
    /* session window 24, per-stream window 1000 (so the session cap binds) */
    mux_config cd = cfg_with(1000, 24, 0, 0);
    mux_config ca = cfg_with(1000, 24, 0, 0);
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);

    int64_t s1 = mux_open(d, NULL, 0);
    int64_t s2 = mux_open(d, NULL, 0);
    pump(d, a, &ld, &la);

    uint8_t buf[100]; memset(buf, 'Z', sizeof buf);
    int64_t w1 = mux_write(d, (uint32_t)s1, buf, 20);
    CHECK_EQ(w1, 20);                /* 20 of 24 session bytes */
    int64_t w2 = mux_write(d, (uint32_t)s2, buf, 20);
    CHECK_EQ(w2, 4);                 /* only 4 left in the session window */
    pump(d, a, &ld, &la);
    CHECK_EQ(la.data_bytes, 24);     /* exactly the session cap crossed */
    mux_session_free(d); mux_session_free(a);
}

/* MAX_STREAMS, local enforcement: the peer advertises its cap in HELLO, so
 * the opener refuses a doomed open up front instead of wasting a round trip. */
static void test_max_streams_local(void) {
    mux_config cd = cfg_with(0,0,16,0);    /* our own cap high */
    mux_config ca = cfg_with(0,0,2,0);     /* acceptor admits only 2 */
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);

    CHECK(mux_open(d, NULL, 0) > 0);
    CHECK(mux_open(d, NULL, 0) > 0);
    CHECK_EQ(mux_open(d, NULL, 0), MUX_ERR_NOMEM); /* 3rd refused locally */
    pump(d, a, &ld, &la);
    CHECK_EQ(count_type(&la, MUX_EV_STREAM_OPENED), 2);
    CHECK(!la.fatal && !ld.fatal);
    mux_session_free(d); mux_session_free(a);
}

/* MAX_STREAMS, defensive path: a misbehaving peer that ignores the cap and
 * forges an over-limit SYN gets that stream RST(REFUSED), session survives. */
static void test_max_streams_defensive(void) {
    mux_config ca = cfg_with(0,0,1,0);     /* acceptor admits only 1 */
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog la = {0};
    /* Hand the acceptor a HELLO so its handshake completes, then two SYNs. */
    mux_config cd = cfg_with(0,0,16,0);
    mux_session *d = mux_session_new(&cd, MUX_DIALER); /* only to craft a HELLO */
    size_t hlen = 0; const uint8_t *hello = mux_send_buf(d, &hlen);
    mux_recv(a, hello, hlen); drain(a, &la);

    /* Dialer uses odd ids; forge two valid, monotonically increasing ones. */
    uint8_t f1[32], f2[32];
    int n1 = mux_craft(f1, sizeof f1, MUX_T_DATA, MUX_F_SYN, 1, NULL, 0);
    int n2 = mux_craft(f2, sizeof f2, MUX_T_DATA, MUX_F_SYN, 3, NULL, 0);
    mux_recv(a, f1, (size_t)n1); drain(a, &la);
    mux_recv(a, f2, (size_t)n2); drain(a, &la);

    CHECK_EQ(count_type(&la, MUX_EV_STREAM_OPENED), 1); /* first admitted */
    CHECK(!la.fatal);                                   /* over-limit is not fatal */
    /* The acceptor should have emitted a RST(REFUSED) for sid 3. */
    size_t olen = 0; const uint8_t *ob = mux_send_buf(a, &olen);
    int saw_rst_refused = 0;
    size_t cur = 0;
    while (cur < olen) {
        mux_frame_t fr; size_t cc = 0;
        if (mux_parse(ob + cur, olen - cur, &fr, &cc) != MUX_OK) break;
        if (fr.type == MUX_T_DATA && (fr.flags & MUX_F_RST) && fr.sid == 3 &&
            fr.len >= 4 && fr.payload &&
            ((uint32_t)fr.payload[3]) == MUX_CODE_REFUSED)
            saw_rst_refused = 1;
        cur += cc;
    }
    CHECK(saw_rst_refused);
    mux_session_free(d); mux_session_free(a);
}

/* Keepalive: PING is emitted on the heartbeat tick and the echo clears it;
 * a missing echo past the timeout kills the session. */
static void test_keepalive(void) {
    mux_config cd = cfg_with(0,0,0, 1000);  /* 1s heartbeat */
    cd.keepalive_timeout_ms = 3000;
    mux_config ca = cfg_with(0,0,0, 1000);
    ca.keepalive_timeout_ms = 3000;
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);

    /* arm timers */
    uint64_t nd = mux_on_timer(d, 0);
    mux_on_timer(a, 0);
    CHECK_EQ(nd, 1000);

    /* at t=1000 dialer fires a PING; pump delivers it and the echo */
    mux_on_timer(d, 1000);
    pump(d, a, &ld, &la);
    /* echo cleared the outstanding ping: a later timer must not declare death */
    uint64_t n2 = mux_on_timer(d, 2000);
    CHECK(n2 != UINT64_MAX);
    CHECK(!ld.fatal);

    /* Now simulate a dead peer: fire a ping but never pump the echo. */
    mux_on_timer(d, 3000);      /* sends ping #2 at t=3000 */
    /* no pump -> no echo; at t=3000+timeout the session must die */
    mux_on_timer(d, 6001);
    drain(d, &ld);
    CHECK(ld.fatal);
    mux_session_free(d); mux_session_free(a);
}

/* Protocol guard: a frame before HELLO is fatal. We forge raw bytes into a
 * fresh acceptor (which has not yet seen any HELLO). */
static void test_proto_data_before_hello(void) {
    mux_config ca = cfg_with(0,0,0,0);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    uint8_t frame[64];
    int n = mux_craft(frame, sizeof frame, MUX_T_DATA, MUX_F_SYN, 2, (const uint8_t*)"x", 1);
    int c = mux_recv(a, frame, (size_t)n);
    evlog la = {0};
    drain(a, &la);
    CHECK(la.fatal);
    (void)c;
    mux_session_free(a);
}

/* Protocol guard: control frame on a non-zero stream id is fatal. */
static void test_proto_control_nonzero_sid(void) {
    mux_config ca = cfg_with(0,0,0,0);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    uint8_t frame[64];
    /* HELLO must use sid 0; sid 5 is illegal */
    int n = mux_craft(frame, sizeof frame, MUX_T_HELLO, 0, 5, NULL, 0);
    mux_recv(a, frame, (size_t)n);
    evlog la = {0};
    drain(a, &la);
    CHECK(la.fatal);
    mux_session_free(a);
}

/* GOAWAY surfaces to the peer and blocks further local opens. */
static void test_goaway(void) {
    mux_config cd = cfg_with(0,0,0,0), ca = cfg_with(0,0,0,0);
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);
    CHECK_EQ(mux_goaway(d, MUX_CODE_NO_ERROR), MUX_OK);
    pump(d, a, &ld, &la);
    CHECK_EQ(count_type(&la, MUX_EV_GOAWAY), 1);
    /* dialer refuses to open after announcing drain */
    CHECK_EQ(mux_open(d, NULL, 0), MUX_ERR_STATE);
    mux_session_free(d); mux_session_free(a);
}

/* SYN→FIN coalesced (open and immediately half-close) yields OPENED+CLOSED. */
static void test_syn_fin_coalesced(void) {
    mux_config cd = cfg_with(0,0,0,0), ca = cfg_with(0,0,0,0);
    mux_session *d = mux_session_new(&cd, MUX_DIALER);
    mux_session *a = mux_session_new(&ca, MUX_ACCEPTOR);
    evlog ld = {0}, la = {0};
    pump(d, a, &ld, &la);
    int64_t sid = mux_open(d, NULL, 0);
    CHECK_EQ(mux_close(d, (uint32_t)sid), MUX_OK);  /* FIN right after SYN */
    pump(d, a, &ld, &la);
    CHECK_EQ(count_type(&la, MUX_EV_STREAM_OPENED), 1);
    CHECK_EQ(count_type(&la, MUX_EV_STREAM_CLOSED), 1);
    mux_session_free(d); mux_session_free(a);
}

int main(void) {
    test_handshake();
    test_open_data_close();
    test_reset();
    test_flow_control_stream();
    test_flow_control_session();
    test_max_streams_local();
    test_max_streams_defensive();
    test_keepalive();
    test_proto_data_before_hello();
    test_proto_control_nonzero_sid();
    test_goaway();
    test_syn_fin_coalesced();

    if (g_fail) { fprintf(stderr, "\n%d check(s) failed\n", g_fail); return 1; }
    printf("all session state-machine tests passed\n");
    return 0;
}
