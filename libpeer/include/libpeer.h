/* libpeer — worker-side SDK over libmux.
 *
 * A worker app links libpeer, dials an edge-peer, and receives inbound logical
 * streams as conn-like handles. The whole point: terminate 100k+ connections
 * over ONE socket (the tunnel) with a blocking, socket-shaped API, so an
 * existing per-connection handler works unchanged and the process pays for one
 * file descriptor instead of one-per-connection.
 *
 * Threading model: lp_connect spins a background I/O thread that solely owns
 * the (single-threaded) mux_session and the tunnel socket, auto-reconnecting
 * with backoff. The blocking lp_* calls below are safe to call from many app
 * threads (the classic one-thread-per-connection style) and from different
 * threads than the one that accepted the stream; they coordinate with the I/O
 * thread through internal buffers and condition variables.
 */
#ifndef LIBPEER_H
#define LIBPEER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lp_client lp_client;
typedef struct lp_stream lp_stream;

typedef struct {
    /* Transport. Exactly one mode:
     *   listen_addr != NULL  -> the worker LISTENS (binds a unix path or
     *                           "host:port") and edge-peer dials in. The worker
     *                           is the mux ACCEPTOR. This is the supervisord
     *                           model: each replica binds its own socket file.
     *   else                 -> the worker DIALS (host:port, or set host to a
     *                           "unix:/path"/"/path" for AF_UNIX). MUX DIALER.
     */
    const char *listen_addr;
    const char *host;        /* edge-peer host (or unix path) to dial        */
    uint16_t    port;        /* edge-peer TCP port (dial mode)               */

    const char *token;       /* pre-shared key (NULL = no auth)              */
    const char *peer_id;     /* advertised identity (NULL ok)                */
    uint32_t    weight;      /* advertised balancing weight (0 => 1)         */
    uint32_t    init_window;     /* per-stream recv window  (0 => default)   */
    uint32_t    session_window;  /* connection recv window  (0 => default)   */
    uint32_t    heartbeat_ms;    /* keepalive interval      (0 => default)   */
} lp_config;

/* Connect (asynchronously) and start the I/O thread. Returns a client handle
 * immediately; the tunnel comes up in the background and reconnects on loss.
 * NULL only on local setup failure (bad config / OOM / thread spawn). */
lp_client *lp_connect(const lp_config *cfg);

/* Stop the I/O thread, drop the tunnel, and free the client. Any streams still
 * open are reset; outstanding blocking calls return promptly. */
void lp_disconnect(lp_client *c);

/* Block until the next inbound stream arrives and return it, or NULL if the
 * client is shutting down. Caller owns the returned stream and must lp_close it. */
lp_stream *lp_accept(lp_client *c);

/* Read up to n bytes. Blocks until data is available. Returns the byte count
 * (> 0), 0 on clean peer half-close (EOF), or -1 on reset/error. */
ssize_t lp_read(lp_stream *s, void *buf, size_t n);

/* Queue n bytes for sending, blocking only while the send buffer is over its
 * high-water mark (flow-control backpressure). Returns n on success, or -1 if
 * the stream/tunnel died. Socket-style: a successful return means the bytes are
 * owned by the SDK, not necessarily on the wire yet. */
ssize_t lp_write(lp_stream *s, const void *buf, size_t n);

/* Half-close the send direction (FIN) and release the caller's reference. The
 * stream is freed once both directions are done. After this the handle is
 * invalid. */
int lp_close(lp_stream *s);

/* The metadata the edge attached at open (client src ip:port / PROXY info),
 * as a view valid for the stream's lifetime. *len set to its length. */
const uint8_t *lp_stream_meta(lp_stream *s, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* LIBPEER_H */
