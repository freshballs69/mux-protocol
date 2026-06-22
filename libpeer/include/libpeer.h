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

/* ------------------------------------------------------------------ */
/* Readiness API — integrate with the app's OWN event loop (select /   */
/* poll / epoll / asyncio) over a SINGLE fd, instead of blocking calls. */
/* ------------------------------------------------------------------ */

#define LP_AGAIN (-2)            /* lp_read_nb/lp_write_nb would block   */

/* Event bits returned by lp_poll. */
enum {
    LP_ACCEPT   = 1,            /* ev.stream is a NEW inbound stream     */
    LP_READABLE = 2,            /* data available (drain with lp_read_nb)*/
    LP_WRITABLE = 4,            /* send buffer drained; retry lp_write_nb*/
    LP_CLOSED   = 8             /* peer FIN / reset                      */
};

typedef struct {
    lp_stream *stream;
    int        events;          /* OR of LP_* bits                       */
} lp_event;

/* A readable fd that signals (level-triggered) when lp_poll has events to
 * return. Register it in the app's loop (e.g. loop.add_reader in asyncio).
 * Calling this switches the client into readiness mode. Returns -1 if none. */
int lp_fileno(lp_client *c);

/* Non-blocking: drain the readiness fd and return up to max ready events.
 * Returns the count (>= 0). Edge-triggered for READABLE/WRITABLE — drain each
 * stream with lp_read_nb until LP_AGAIN. */
int lp_poll(lp_client *c, lp_event *out, int max);

/* Non-blocking read: > 0 bytes, 0 on EOF, -1 on reset, LP_AGAIN if no data. */
ssize_t lp_read_nb(lp_stream *s, void *buf, size_t n);

/* Non-blocking write: returns n queued, or LP_AGAIN if the send buffer is full
 * (a later LP_WRITABLE event will fire). -1 on a dead stream. */
ssize_t lp_write_nb(lp_stream *s, const void *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* LIBPEER_H */
