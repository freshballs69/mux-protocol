/* edge-peer — LAN-side router & balancer.
 *
 *   ./edge-peer --connect EDGE_HOST:PORT --worker ADDR [--worker ADDR ...] [--token KEY]
 *
 * Dials the edge's uplink port (upstream) and a pool of workers (downstream),
 * SWRR-balancing each inbound stream onto a worker. Workers may listen on unix
 * sockets — the supervisord model where each replica binds its own socket file:
 *
 *   --worker /run/app_00.sock --worker /run/app_01.sock ...
 *   --worker 127.0.0.1:9000   (TCP also works)
 *
 * Backend mode (terminate each stream to one plain TCP backend, no balancing)
 * is kept for quick tests:
 *
 *   ./edge-peer --connect EDGE:PORT --backend HOST:PORT
 */
#include "router.h"
#include "relay.h"
#include "net.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig){ (void)sig; g_stop = 1; ep_request_stop(); relay_request_stop(); }

static void usage(const char *p) {
    fprintf(stderr,
        "usage: %s --connect EDGE_HOST:PORT (--worker ADDR ... | --backend HOST:PORT) [--token KEY]\n"
        "  --connect  edge uplink to dial\n"
        "  --worker   a worker tunnel to dial (repeatable); unix path or host:port\n"
        "  --backend  OR terminate each stream to this one TCP backend (no balancing)\n"
        "  --token    pre-shared key (or env MUX_TOKEN)\n", p);
}

/* ---- backend (relay) mode: dial edge, terminate streams to one backend ---- */
static int run_backend_mode(const char *edge, const char *backend, const char *token) {
    char eh[256], bh[256]; uint16_t ep, bp;
    if (net_parse_addr(edge, eh, sizeof eh, &ep) != 0) { fprintf(stderr,"bad --connect\n"); return 2; }
    if (net_parse_addr(backend, bh, sizeof bh, &bp) != 0) { fprintf(stderr,"bad --backend\n"); return 2; }
    int backoff = 250;
    while (!g_stop) {
        int fd = net_dial(eh, ep);
        int ok = 0;
        if (fd >= 0) {
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            for (;;) { int rc = poll(&p,1,300); if (g_stop) break; if (rc<0){if(errno==EINTR)continue;break;} if (rc==0) continue; ok = net_socket_error(fd)==0; break; }
        }
        if (!ok) { if (fd>=0) close(fd); struct timespec ts={backoff/1000,(backoff%1000)*1000000L}; nanosleep(&ts,NULL); backoff = backoff<8000?backoff*2:8000; continue; }
        backoff = 250;
        relay_opts o; memset(&o,0,sizeof o);
        o.role = MUX_DIALER; o.token = token; o.peer_id = "edge-peer";
        o.public_listen_fd = -1; o.backend_host = bh; o.backend_port = bp;
        relay *r = relay_new(fd, &o);
        if (!r) { close(fd); continue; }
        relay_run(r); relay_free(r);
        fprintf(stderr, "[edge-peer] edge link lost; reconnecting\n");
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *connect_addr = NULL, *backend = NULL, *token = NULL, *peer_id = "edge-peer";
    const char *workers[256]; int nworkers = 0;
    long heartbeat = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--connect") && i+1<argc) connect_addr = argv[++i];
        else if (!strcmp(argv[i], "--worker") && i+1<argc) { if (nworkers < 256) workers[nworkers++] = argv[++i]; }
        else if (!strcmp(argv[i], "--backend") && i+1<argc) backend = argv[++i];
        else if (!strcmp(argv[i], "--token") && i+1<argc) token = argv[++i];
        else if (!strcmp(argv[i], "--peer-id") && i+1<argc) peer_id = argv[++i];
        else if (!strcmp(argv[i], "--heartbeat") && i+1<argc) heartbeat = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if (!connect_addr || (nworkers == 0 && !backend)) { usage(argv[0]); return 2; }
    if (!token) token = getenv("MUX_TOKEN");

    signal(SIGINT, on_sigint); signal(SIGTERM, on_sigint); signal(SIGPIPE, SIG_IGN);

    if (backend && nworkers == 0)
        return run_backend_mode(connect_addr, backend, token);

    ep_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.edge_addr = connect_addr;
    cfg.workers = workers; cfg.nworkers = nworkers;
    cfg.token = token; cfg.peer_id = peer_id;
    cfg.heartbeat_ms = (uint32_t)heartbeat;
    int rc = ep_run(&cfg);
    fprintf(stderr, "[edge-peer] bye\n");
    return rc;
}
