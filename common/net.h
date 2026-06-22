/* Tiny blocking-socket helpers shared by the daemons. Portable POSIX
 * (Linux + macOS); the event loop uses poll(), so all fds are non-blocking. */
#ifndef MUX_NET_H
#define MUX_NET_H

#include <stddef.h>
#include <stdint.h>

/* Create a non-blocking TCP listener bound to host:port (host NULL/"" => any),
 * with SO_REUSEADDR (+ SO_REUSEPORT where available). Returns fd or -1. */
int net_listen(const char *host, uint16_t port, int backlog);

/* Accept a connection on a listener, returning a non-blocking fd, or -1 with
 * errno set (EAGAIN when nothing pending). The peer ip:port is written to
 * `peer` (size `peerlen`) when non-NULL. */
int net_accept(int listen_fd, char *peer, size_t peerlen);

/* Non-blocking connect to host:port. Returns a fd that may still be
 * connecting (EINPROGRESS): poll for writability, then net_socket_error().
 * Returns -1 on immediate failure. */
int net_dial(const char *host, uint16_t port);

/* Pending SO_ERROR for a socket (0 = connected/ok). */
int net_socket_error(int fd);

int  net_set_nonblock(int fd);
int  net_set_nodelay(int fd);

/* Fill buf with n cryptographically-random bytes. Returns 0 on success. */
int  os_random(void *buf, size_t n);

/* Parse "host:port" (or ":port"/"port") into host + port. Returns 0 on success.
 * `host_out` gets the host (may be empty for any); cap is its size. */
int net_parse_addr(const char *s, char *host_out, size_t cap, uint16_t *port_out);

#endif /* MUX_NET_H */
