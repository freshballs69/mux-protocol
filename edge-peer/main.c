/* edge-peer — LAN-side daemon (minimal v1: single backend, no balancing yet).
 *
 *   ./edge-peer --connect HOST:PORT --backend HOST:PORT [--token KEY]
 *
 * Dials the edge's uplink port (edge-peer is the more-NAT'd side, so it dials),
 * then for each inbound logical stream opens a TCP connection to --backend and
 * pipes both ways. This makes a complete proxy:
 *
 *   client -> edge:accept-port -> (mux tunnel) -> edge-peer -> backend
 *
 * Auto-reconnects to the edge with backoff. Balancing across multiple workers
 * and the SWRR router are a later milestone; this terminates to one backend.
 */
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
static void on_sigint(int sig) { (void)sig; g_stop = 1; relay_request_stop(); }

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --connect HOST:PORT --backend HOST:PORT [--token KEY]\n"
        "          [--peer-id ID] [--weight W] [--heartbeat MS]\n"
        "  --connect  the edge uplink address to dial\n"
        "  --backend  where to forward each inbound stream\n"
        "  --token    pre-shared key (or env MUX_TOKEN); omitted = no auth\n",
        prog);
}

/* Block until a non-blocking connect completes or fails. Returns 0 on success. */
static int finish_connect(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLOUT };
    for (;;) {
        int rc = poll(&p, 1, 500);
        if (g_stop) return -1;
        if (rc < 0) { if (errno == EINTR) continue; return -1; }
        if (rc == 0) continue;
        return net_socket_error(fd) == 0 ? 0 : -1;
    }
}

int main(int argc, char **argv) {
    const char *connect_addr = NULL, *backend_addr = NULL;
    const char *token = NULL, *peer_id = "edge-peer";
    long weight = 1, heartbeat = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--connect") && i+1 < argc) connect_addr = argv[++i];
        else if (!strcmp(argv[i], "--backend") && i+1 < argc) backend_addr = argv[++i];
        else if (!strcmp(argv[i], "--token") && i+1 < argc) token = argv[++i];
        else if (!strcmp(argv[i], "--peer-id") && i+1 < argc) peer_id = argv[++i];
        else if (!strcmp(argv[i], "--weight") && i+1 < argc) weight = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--heartbeat") && i+1 < argc) heartbeat = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if (!connect_addr || !backend_addr) { usage(argv[0]); return 2; }
    if (!token) token = getenv("MUX_TOKEN");

    char edge_host[256], be_host[256];
    uint16_t edge_port, be_port;
    if (net_parse_addr(connect_addr, edge_host, sizeof edge_host, &edge_port) != 0) {
        fprintf(stderr, "bad --connect: %s\n", connect_addr); return 2;
    }
    if (net_parse_addr(backend_addr, be_host, sizeof be_host, &be_port) != 0) {
        fprintf(stderr, "bad --backend: %s\n", backend_addr); return 2;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "[edge-peer] edge %s  backend %s  auth %s\n",
            connect_addr, backend_addr, token ? "on" : "OFF");

    int backoff_ms = 250;
    while (!g_stop) {
        int fd = net_dial(edge_host, edge_port);
        if (fd < 0 || finish_connect(fd) != 0) {
            if (fd >= 0) close(fd);
            fprintf(stderr, "[edge-peer] connect to %s failed; retry in %dms\n", connect_addr, backoff_ms);
            struct timespec ts = { backoff_ms / 1000, (backoff_ms % 1000) * 1000000L };
            nanosleep(&ts, NULL);
            backoff_ms = backoff_ms < 8000 ? backoff_ms * 2 : 8000; /* capped exp backoff */
            continue;
        }
        backoff_ms = 250;
        fprintf(stderr, "[edge-peer] connected to edge %s\n", connect_addr);

        relay_opts opts;
        memset(&opts, 0, sizeof opts);
        opts.role          = MUX_DIALER;        /* edge-peer dials the edge */
        opts.token         = token;
        opts.peer_id       = peer_id;
        opts.weight        = (uint32_t)weight;
        opts.heartbeat_ms  = (uint32_t)heartbeat;
        opts.public_listen_fd = -1;
        opts.backend_host  = be_host;           /* terminate each stream here */
        opts.backend_port  = be_port;

        relay *r = relay_new(fd, &opts);
        if (!r) { close(fd); continue; }
        relay_run(r);
        relay_free(r);
        fprintf(stderr, "[edge-peer] disconnected from edge\n");
    }

    fprintf(stderr, "[edge-peer] bye\n");
    return 0;
}
