/* Integration test for libpeer: a controlled "edge-peer" (this file) opens a
 * stream toward a libpeer worker thread, which echoes. Exercises the whole
 * threaded facade — accept, read, write, half-close — over a real socket,
 * under ASan. */
#include "libpeer.h"
#include "mux.h"
#include "net.h"
#include "auth.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); g_fail++; } } while (0)

/* ---- worker: echo each inbound stream until EOF ---- */
static const char *g_host = "127.0.0.1";
static uint16_t    g_port;
static char        g_meta_seen[64];
static int         g_meta_len_seen = -1;

static void *worker_main(void *arg) {
    (void)arg;
    lp_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.host = g_host; cfg.port = g_port; cfg.token = "k"; cfg.weight = 4;
    lp_client *c = lp_connect(&cfg);
    if (!c) return NULL;
    lp_stream *s = lp_accept(c);
    if (s) {
        size_t ml = 0; const uint8_t *m = lp_stream_meta(s, &ml);
        g_meta_len_seen = (int)ml;
        if (ml && ml < sizeof g_meta_seen) memcpy(g_meta_seen, m, ml);
        uint8_t buf[4096];
        for (;;) {
            ssize_t n = lp_read(s, buf, sizeof buf);
            if (n <= 0) break;           /* EOF or error */
            ssize_t off = 0;
            while (off < n) { ssize_t w = lp_write(s, buf + off, (size_t)(n - off)); if (w <= 0) break; off += w; }
        }
        lp_close(s);
    }
    lp_disconnect(c);
    return NULL;
}

/* ---- server side: drive a mux ACCEPTOR over one accepted socket ---- */
int main(void) {
    int lfd = net_listen("127.0.0.1", 0, 16);
    CHECK(lfd >= 0);
    if (lfd < 0) return 1;
    struct sockaddr_in sa; socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);

    pthread_t wt;
    pthread_create(&wt, NULL, worker_main, NULL);

    /* accept the worker's tunnel (poll until it dials in) */
    int fd = -1;
    for (int i = 0; i < 200 && fd < 0; i++) {
        struct pollfd p = { .fd = lfd, .events = POLLIN };
        if (poll(&p, 1, 50) > 0) fd = net_accept(lfd, NULL, 0);
    }
    CHECK(fd >= 0);
    if (fd < 0) return 1;

    mux_config mc; memset(&mc, 0, sizeof mc);
    mc.weight = 1;
    /* auth: server presents proof over its own nonce; the worker verifies it.
     * Mirrors libpeer's scheme using token "k". */
    static uint8_t nonce[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    static uint8_t proof[32];
    mux_auth_proof("k", 1, nonce, sizeof nonce, proof);
    mc.nonce = nonce; mc.nonce_len = sizeof nonce;
    mc.auth = proof; mc.auth_len = sizeof proof;

    mux_session *m = mux_session_new(&mc, MUX_ACCEPTOR);
    CHECK(m != NULL);

    const char *meta = "src=9.9.9.9:1234";
    int opened = 0, sid = -1;
    char echo[64]; size_t echo_len = 0;
    int closed = 0;

    /* drive until we've sent ping+fin and received the echoed ping + close */
    for (int iter = 0; iter < 2000 && !closed; iter++) {
        size_t outlen = 0;
        const uint8_t *ob = mux_send_buf(m, &outlen);
        short ev = POLLIN | (outlen ? POLLOUT : 0);
        struct pollfd p = { .fd = fd, .events = ev };
        int rc = poll(&p, 1, 50);
        if (rc < 0) break;

        if (p.revents & POLLOUT) {
            ssize_t w = write(fd, ob, outlen);
            if (w > 0) mux_send_advance(m, (size_t)w);
        }
        if (p.revents & POLLIN) {
            uint8_t rb[8192];
            ssize_t n = read(fd, rb, sizeof rb);
            if (n <= 0) break;
            mux_recv(m, rb, (size_t)n);
            mux_event e;
            while (mux_next_event(m, &e)) {
                if (e.type == MUX_EV_PEER_HELLO && !opened) {
                    int64_t s = mux_open(m, (const uint8_t *)meta, strlen(meta));
                    if (s >= 0) {
                        sid = (int)s; opened = 1;
                        mux_write(m, (uint32_t)sid, (const uint8_t *)"ping", 4);
                        mux_close(m, (uint32_t)sid);   /* half-close after the request */
                    }
                } else if (e.type == MUX_EV_STREAM_DATA && (int)e.sid == sid) {
                    if (echo_len + e.u.data.data_len < sizeof echo) {
                        memcpy(echo + echo_len, e.u.data.data, e.u.data.data_len);
                        echo_len += e.u.data.data_len;
                    }
                    mux_consume(m, e.sid, e.u.data.data_len);
                } else if (e.type == MUX_EV_STREAM_CLOSED && (int)e.sid == sid) {
                    closed = 1;
                }
            }
        }
        /* keepalive */
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        mux_on_timer(m, (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
    }

    CHECK(opened);
    CHECK(echo_len == 4);
    CHECK(memcmp(echo, "ping", 4) == 0);
    CHECK(closed);
    CHECK(g_meta_len_seen == (int)strlen(meta));
    CHECK(memcmp(g_meta_seen, meta, strlen(meta)) == 0);

    mux_session_free(m);
    close(fd);
    close(lfd);
    pthread_join(wt, NULL);

    if (g_fail) { fprintf(stderr, "\n%d check(s) failed\n", g_fail); return 1; }
    printf("libpeer integration test passed\n");
    return 0;
}
