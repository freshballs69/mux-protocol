#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/resource.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int net_set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int net_set_nodelay(int fd) {
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

/* Enable TCP keepalive so the KERNEL reaps a dead peer (a half-open "zombie"
 * connection left when the peer vanished without a FIN — NAT timeout, host
 * crash, frozen process). After `idle` seconds idle, probe every `intvl`
 * seconds; declare dead after `cnt` unanswered probes (~idle + intvl*cnt). The
 * relay then sees the socket close and accepts a fresh tunnel — no polling, no
 * preemption, and it can NEVER fire on a live connection. Best-effort; unknown
 * options are ignored. No-op on AF_UNIX (the setsockopts simply fail). */
int net_set_keepalive(int fd, int idle, int intvl, int cnt) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one) < 0) return -1;
#ifdef TCP_KEEPIDLE
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
#elif defined(TCP_KEEPALIVE)            /* macOS/BSD: idle time, in seconds */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle, sizeof idle);
#endif
#ifdef TCP_KEEPINTVL
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
#endif
#ifdef TCP_KEEPCNT
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
#endif
    (void)intvl; (void)cnt;
    return 0;
}

int net_listen(const char *host, uint16_t port, int backlog) {
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;
    const char *node = (host && host[0]) ? host : NULL;
    if (getaddrinfo(node, portstr, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
            listen(fd, backlog) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0)
        net_set_nonblock(fd);
    return fd;
}

static void fill_peer(const struct sockaddr *sa, socklen_t sl, char *peer, size_t peerlen) {
    if (!peer || peerlen == 0) return;
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo(sa, sl, host, sizeof host, serv, sizeof serv,
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        snprintf(peer, peerlen, "%s:%s", host, serv);
    else
        snprintf(peer, peerlen, "?");
}

int net_accept(int listen_fd, char *peer, size_t peerlen) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = accept(listen_fd, (struct sockaddr *)&ss, &sl);
    if (fd < 0)
        return -1;
    net_set_nonblock(fd);
    net_set_nodelay(fd);
    fill_peer((struct sockaddr *)&ss, sl, peer, peerlen);
    return fd;
}

int net_dial(const char *host, uint16_t port) {
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        net_set_nonblock(fd);
        net_set_nodelay(fd);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r == 0 || errno == EINPROGRESS)
            break;                          /* connected or in progress */
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int unix_addr(struct sockaddr_un *sa, const char *path) {
    memset(sa, 0, sizeof *sa);
    sa->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa->sun_path)
        return -1;
    strncpy(sa->sun_path, path, sizeof sa->sun_path - 1);
    return 0;
}

int net_listen_unix(const char *path, int backlog) {
    struct sockaddr_un sa;
    if (unix_addr(&sa, path) != 0)
        return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    unlink(path);                       /* clear a stale socket file */
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }
    net_set_nonblock(fd);
    return fd;
}

int net_dial_unix(const char *path) {
    struct sockaddr_un sa;
    if (unix_addr(&sa, path) != 0)
        return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    net_set_nonblock(fd);
    int r = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (r == 0 || errno == EINPROGRESS)
        return fd;
    close(fd);
    return -1;
}

int net_addr_is_unix(const char *addr) {
    if (!addr) return 0;
    return strncmp(addr, "unix:", 5) == 0 || addr[0] == '/';
}

static const char *unix_path_of(const char *addr) {
    return (strncmp(addr, "unix:", 5) == 0) ? addr + 5 : addr;
}

int net_listen_addr(const char *addr, int backlog) {
    if (net_addr_is_unix(addr))
        return net_listen_unix(unix_path_of(addr), backlog);
    char host[256]; uint16_t port;
    if (net_parse_addr(addr, host, sizeof host, &port) != 0)
        return -1;
    return net_listen(host[0] ? host : NULL, port, backlog);
}

int net_dial_addr(const char *addr) {
    if (net_addr_is_unix(addr))
        return net_dial_unix(unix_path_of(addr));
    char host[256]; uint16_t port;
    if (net_parse_addr(addr, host, sizeof host, &port) != 0)
        return -1;
    return net_dial(host, port);
}

int net_socket_error(int fd) {
    int err = 0;
    socklen_t len = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
        return errno;
    return err;
}

long net_raise_fd_limit(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return -1;
    rlim_t want = rl.rlim_max;
#ifdef __APPLE__
    /* macOS caps the effective NOFILE at kern.maxfilesperproc; OPEN_MAX is the
     * portable conservative ceiling that setrlimit will accept. */
    if (want == RLIM_INFINITY || want > OPEN_MAX) want = OPEN_MAX;
#endif
    rl.rlim_cur = want;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        /* fall back: try the current hard limit verbatim */
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) return (long)rl.rlim_cur;
        return -1;
    }
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return -1;
    return (long)rl.rlim_cur;
}

int os_random(void *buf, size_t n) {
    /* /dev/urandom is universally available on Linux and macOS. */
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp)
        return -1;
    size_t got = fread(buf, 1, n, fp);
    fclose(fp);
    return got == n ? 0 : -1;
}

int net_parse_addr(const char *s, char *host_out, size_t cap, uint16_t *port_out) {
    if (!s || !host_out || !port_out || cap == 0)
        return -1;
    const char *colon = strrchr(s, ':');
    if (!colon) {
        /* bare port */
        host_out[0] = 0;
        long p = strtol(s, NULL, 10);
        if (p <= 0 || p > 65535) return -1;
        *port_out = (uint16_t)p;
        return 0;
    }
    size_t hlen = (size_t)(colon - s);
    if (hlen >= cap) return -1;
    memcpy(host_out, s, hlen);
    host_out[hlen] = 0;
    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) return -1;
    *port_out = (uint16_t)p;
    return 0;
}
