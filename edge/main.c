/* edge — public-facing VPS daemon.
 *
 *   ./edge --accept-port 5000 --mux-port 5001 [--token KEY]
 *
 * Accepts public TCP on --accept-port and multiplexes each connection into a
 * logical stream over the uplink tunnel. The tunnel lands on --mux-port, where
 * an edge-peer dials in (edge-peer is the more-NAT'd side, so it dials; edge is
 * the public side, so it INITIATES streams). One uplink at a time per process.
 *
 * To use every core on a multi-core VPS, pass --procs N: the master forks N
 * workers that SHARE --accept-port via SO_REUSEPORT (the kernel spreads client
 * SYNs across them, one accept queue per core) and each listens on its own
 * uplink port --mux-port + i. The edge-peer then dials all N ports
 * (--edge HOST:5001 --edge HOST:5002 ...), spreading public ingress across the
 * whole box. Combine with multiple VPSes for cross-machine spread.
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
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; relay_request_stop(); }

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --accept-port N --mux-port N [--procs K] [--token KEY] [--peer-id ID]\n"
        "          [--weight W] [--heartbeat MS]\n"
        "  --accept-port  public listener for client TCP\n"
        "  --mux-port     uplink listener; an edge-peer dials in here\n"
        "  --procs        fork K workers sharing --accept-port (SO_REUSEPORT) to\n"
        "                 use all cores; worker i listens on uplink --mux-port + i\n"
        "  --max-streams  per-proc cap on concurrent client conns (default 8000,\n"
        "                 0 = unlimited); at the cap the edge stops accepting so\n"
        "                 it sheds load instead of drowning in half-open fds\n"
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

/* Configuration shared by every worker (only mux_port differs per worker). */
typedef struct {
    long accept_port, weight, heartbeat, max_streams;
    const char *token, *peer_id;
} edge_cfg;

/* One worker: bind accept+uplink ports and serve uplinks until stopped. */
static int run_edge_proc(const edge_cfg *c, long mux_port) {
    long fdlim = net_raise_fd_limit();      /* edge holds one fd per public conn */
    fprintf(stderr, "[edge %ld] fd limit: %ld\n", mux_port, fdlim);

    /* Large accept backlog so a burst of tens of thousands of simultaneous
     * client SYNs is queued (not dropped) while the accept loop drains it. The
     * kernel still caps this at net.core.somaxconn — raise that too (the
     * container sets it via sysctls). Each worker binds its OWN accept socket;
     * SO_REUSEPORT gives the kernel a separate accept queue per worker. */
    int public_fd = net_listen(NULL, (uint16_t)c->accept_port, 65535);
    if (public_fd < 0) { fprintf(stderr, "[edge] cannot listen on :%ld\n", c->accept_port); return 1; }
    int mux_fd = net_listen(NULL, (uint16_t)mux_port, 16);
    if (mux_fd < 0) { fprintf(stderr, "[edge] cannot listen on :%ld\n", mux_port); return 1; }

    fprintf(stderr, "[edge] public :%ld  uplink :%ld  auth %s\n",
            c->accept_port, mux_port, c->token ? "on" : "OFF");

    while (!g_stop) {
        int uplink = accept_uplink(mux_fd);
        if (uplink < 0) break;
        /* Keepalive so a zombie edge-peer (vanished with no FIN) is reaped by the
         * kernel in ~14s; the relay then sees EOF and accepts the next uplink. */
        net_set_keepalive(uplink, 8, 3, 2);

        relay_opts opts;
        memset(&opts, 0, sizeof opts);
        opts.role             = MUX_ACCEPTOR;   /* edge accepts the TCP dial */
        opts.token            = c->token;
        opts.peer_id          = c->peer_id;
        opts.weight           = (uint32_t)c->weight;
        opts.heartbeat_ms     = (uint32_t)c->heartbeat;
        opts.public_listen_fd = public_fd;      /* edge opens streams for public conns */
        opts.max_streams      = (int)c->max_streams; /* backpressure cap (per proc) */
        opts.backend_host     = NULL;

        relay *r = relay_new(uplink, &opts);
        if (!r) { close(uplink); continue; }
        relay_run(r);
        relay_free(r);
        close(uplink);                          /* drop the old uplink fd (no leak) */
        fprintf(stderr, "[edge] uplink gone; awaiting next\n");
    }

    close(public_fd);
    close(mux_fd);
    fprintf(stderr, "[edge] bye\n");
    return 0;
}

/* Master: fork `procs` workers; if any exits, stop them all and return so the
 * orchestrator restarts the whole set cleanly. */
static int run_supervisor(const edge_cfg *c, long mux_base, long procs) {
    pid_t *kids = calloc((size_t)procs, sizeof *kids);
    if (!kids) return 1;
    for (long i = 0; i < procs; i++) {
        pid_t pid = fork();
        if (pid == 0) { free(kids); _exit(run_edge_proc(c, mux_base + i)); }
        if (pid < 0) { fprintf(stderr, "[edge] fork failed\n"); break; }
        kids[i] = pid;
    }
    fprintf(stderr, "[edge] supervisor: %ld workers, uplink :%ld..%ld\n",
            procs, mux_base, mux_base + procs - 1);

    /* Wait for a worker to exit (or a signal), then bring everyone down. */
    while (!g_stop) {
        int st; pid_t w = waitpid(-1, &st, 0);
        if (w > 0) { fprintf(stderr, "[edge] worker %d exited; stopping all\n", w); break; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0) break;
    }
    for (long i = 0; i < procs; i++) if (kids[i] > 0) kill(kids[i], SIGTERM);
    for (long i = 0; i < procs; i++) { int st; if (kids[i] > 0) waitpid(kids[i], &st, 0); }
    free(kids);
    fprintf(stderr, "[edge] supervisor bye\n");
    return 0;
}

int main(int argc, char **argv) {
    long accept_port = 0, mux_port = 0, weight = 1, heartbeat = 0, procs = 1;
    long max_streams = 8000;                /* per-proc backpressure cap (0 = off) */
    const char *token = NULL, *peer_id = "edge";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--accept-port") && i+1 < argc) accept_port = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--mux-port") && i+1 < argc) mux_port = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--procs") && i+1 < argc) procs = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--token") && i+1 < argc) token = argv[++i];
        else if (!strcmp(argv[i], "--peer-id") && i+1 < argc) peer_id = argv[++i];
        else if (!strcmp(argv[i], "--weight") && i+1 < argc) weight = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--heartbeat") && i+1 < argc) heartbeat = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--max-streams") && i+1 < argc) max_streams = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if (accept_port <= 0 || accept_port > 65535 || mux_port <= 0 || mux_port > 65535) {
        usage(argv[0]); return 2;
    }
    if (procs < 1) procs = 1;
    if (mux_port + procs - 1 > 65535) { fprintf(stderr, "[edge] --procs overflows mux-port range\n"); return 2; }
    if (!token) token = getenv("MUX_TOKEN");

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    edge_cfg c = { accept_port, weight, heartbeat, max_streams, token, peer_id };
    if (procs > 1) return run_supervisor(&c, mux_port, procs);
    return run_edge_proc(&c, mux_port);
}
