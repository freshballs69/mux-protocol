/* http_worker — a tiny worker built on libpeer.
 *
 *   ./http_worker --listen /run/app_00.sock --token KEY --id W0 --weight 4
 *
 * Listens on a unix (or TCP) socket for the edge-peer to dial in, then handles
 * each inbound logical stream as a connection: reads the HTTP request and
 * replies with a fixed 200 that names this worker, so balancing across a pool
 * is visible. One detached thread per stream demonstrates the conn-like API at
 * concurrency over a single tunnel fd.
 */
#include "libpeer.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *g_id = "W?";

static void serve(lp_stream *s) {
    char buf[8192];
    /* read the request headers (best-effort; stop at end of headers or EOF) */
    size_t total = 0;
    for (;;) {
        ssize_t n = lp_read(s, buf + total, sizeof buf - total - 1);
        if (n <= 0) break;
        total += (size_t)n;
        buf[total] = 0;
        if (strstr(buf, "\r\n\r\n") || total >= sizeof buf - 1) break;
    }
    char body[128];
    int blen = snprintf(body, sizeof body, "handled by worker %s\n", g_id);
    char resp[256];
    int rlen = snprintf(resp, sizeof resp,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        blen, body);
    ssize_t off = 0;
    while (off < rlen) { ssize_t w = lp_write(s, resp + off, (size_t)(rlen - off)); if (w <= 0) break; off += w; }
    lp_close(s);
}

/* Bounded thread pool: each thread pulls streams off the shared accept queue
 * (lp_accept is safe for concurrent callers) and serves them synchronously. No
 * per-request thread creation, so the worker survives huge connection churn. */
static lp_client *g_client;
static void *pool_thread(void *arg) {
    (void)arg;
    for (;;) {
        lp_stream *s = lp_accept(g_client);
        if (!s) break;
        serve(s);
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *listen_addr = NULL, *token = NULL;
    long weight = 1, pool = 64;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--listen") && i+1<argc) listen_addr = argv[++i];
        else if (!strcmp(argv[i], "--token") && i+1<argc) token = argv[++i];
        else if (!strcmp(argv[i], "--id") && i+1<argc) g_id = argv[++i];
        else if (!strcmp(argv[i], "--weight") && i+1<argc) weight = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--pool") && i+1<argc) pool = strtol(argv[++i], NULL, 10);
        else { fprintf(stderr, "usage: %s --listen ADDR --token KEY --id NAME --weight W --pool N\n", argv[0]); return 2; }
    }
    if (!listen_addr) { fprintf(stderr, "need --listen\n"); return 2; }
    if (!token) token = getenv("MUX_TOKEN");
    if (pool < 1) pool = 1;
    signal(SIGPIPE, SIG_IGN);

    lp_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.listen_addr = listen_addr;          /* worker LISTENS; edge-peer dials in */
    cfg.token = token; cfg.peer_id = g_id; cfg.weight = (uint32_t)weight;
    g_client = lp_connect(&cfg);
    if (!g_client) { fprintf(stderr, "lp_connect failed\n"); return 1; }
    fprintf(stderr, "[%s] listening on %s weight=%ld pool=%ld\n", g_id, listen_addr, weight, pool);

    pthread_t *ts = (pthread_t *)calloc((size_t)pool, sizeof *ts);
    for (long i = 0; i < pool; i++) pthread_create(&ts[i], NULL, pool_thread, NULL);
    for (long i = 0; i < pool; i++) pthread_join(ts[i], NULL);
    free(ts);
    lp_disconnect(g_client);
    return 0;
}
