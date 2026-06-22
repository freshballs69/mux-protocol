/* edge — public-facing VPS daemon.
 *
 *   ./edge --accept-port 5000 --mux-port 5001 [--token KEY]
 *
 * Accepts public TCP on --accept-port and multiplexes each connection into a
 * logical stream over the uplink tunnel. The tunnel lands on --mux-port, where
 * an edge-peer dials in (edge-peer is the more-NAT'd side, so it dials; edge is
 * the public side, so it INITIATES streams). One uplink at a time in v1.
 *
 * The pre-shared key comes from --token or the MUX_TOKEN environment variable.
 */
#include "relay.h"
#include "net.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; relay_request_stop(); }

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --accept-port N --mux-port N [--token KEY] [--peer-id ID]\n"
        "          [--weight W] [--heartbeat MS]\n"
        "  --accept-port  public listener for client TCP\n"
        "  --mux-port     uplink listener; an edge-peer dials in here\n"
        "  --token        pre-shared key (or env MUX_TOKEN); omitted = no auth\n",
        prog);
}

/* Wait for and accept a single uplink connection, honoring the stop flag. */
static int accept_uplink(int mux_fd) {
    while (!g_stop) {
        struct pollfd p = { .fd = mux_fd, .events = POLLIN };
        int rc = poll(&p, 1, 500);
        if (rc < 0) { if (errno == EINTR) continue; return -1; }
        if (rc == 0) continue;
        char peer[128];
        int fd = net_accept(mux_fd, peer, sizeof peer);
        if (fd >= 0) {
            fprintf(stderr, "[edge] uplink connected from %s\n", peer);
            return fd;
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    long accept_port = 0, mux_port = 0, weight = 1, heartbeat = 0;
    const char *token = NULL, *peer_id = "edge";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--accept-port") && i+1 < argc) accept_port = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--mux-port") && i+1 < argc) mux_port = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--token") && i+1 < argc) token = argv[++i];
        else if (!strcmp(argv[i], "--peer-id") && i+1 < argc) peer_id = argv[++i];
        else if (!strcmp(argv[i], "--weight") && i+1 < argc) weight = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--heartbeat") && i+1 < argc) heartbeat = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if (accept_port <= 0 || accept_port > 65535 || mux_port <= 0 || mux_port > 65535) {
        usage(argv[0]); return 2;
    }
    if (!token) token = getenv("MUX_TOKEN");

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    int public_fd = net_listen(NULL, (uint16_t)accept_port, 1024);
    if (public_fd < 0) { fprintf(stderr, "[edge] cannot listen on :%ld\n", accept_port); return 1; }
    int mux_fd = net_listen(NULL, (uint16_t)mux_port, 16);
    if (mux_fd < 0) { fprintf(stderr, "[edge] cannot listen on :%ld\n", mux_port); return 1; }

    fprintf(stderr, "[edge] public :%ld  uplink :%ld  auth %s\n",
            accept_port, mux_port, token ? "on" : "OFF");

    while (!g_stop) {
        int uplink = accept_uplink(mux_fd);
        if (uplink < 0) break;

        relay_opts opts;
        memset(&opts, 0, sizeof opts);
        opts.role             = MUX_ACCEPTOR;   /* edge accepts the TCP dial */
        opts.token            = token;
        opts.peer_id          = peer_id;
        opts.weight           = (uint32_t)weight;
        opts.heartbeat_ms     = (uint32_t)heartbeat;
        opts.public_listen_fd = public_fd;      /* edge opens streams for public conns */
        opts.backend_host     = NULL;

        relay *r = relay_new(uplink, &opts);
        if (!r) { close(uplink); continue; }
        relay_run(r);
        relay_free(r);
        fprintf(stderr, "[edge] uplink gone; awaiting next\n");
    }

    close(public_fd);
    close(mux_fd);
    fprintf(stderr, "[edge] bye\n");
    return 0;
}
