/* relay — the shared poll() engine that pipes sockets <-> mux streams.
 *
 * Both daemons are the same machine with one knob flipped:
 *   - edge:      accepts PUBLIC sockets and OPENS a stream per socket
 *                (stream initiator). Set public_listen_fd.
 *   - edge-peer: ACCEPTS streams and DIALS a backend per stream
 *                (stream receiver). Set backend_host/backend_port.
 *
 * The relay owns one tunnel fd + one mux_session and maps each logical stream
 * 1:1 to a socket, piping both ways with flow-control-aware backpressure.
 */
#ifndef MUX_RELAY_H
#define MUX_RELAY_H

#include "mux.h"

#include <stdint.h>

typedef struct relay relay;

typedef struct {
    mux_role    role;            /* tunnel session role (parity/handshake)   */
    const char *token;           /* PSK; NULL disables auth                  */
    const char *peer_id;         /* advertised identity (NULL ok)            */
    uint32_t    weight;          /* advertised balancing weight              */
    uint32_t    init_window;     /* per-stream recv window (0 => default)    */
    uint32_t    session_window;  /* connection recv window (0 => default)    */
    uint32_t    heartbeat_ms;    /* keepalive interval (0 => default 15s)    */

    int         public_listen_fd; /* edge: accept here. -1 if unused         */
    int         max_streams;      /* edge: cap on concurrent public conns.    */
                                  /* At the cap the edge stops accepting (new */
                                  /* clients queue in the kernel backlog)     */
                                  /* instead of piling up half-open fds and   */
                                  /* drowning. 0 = unlimited.                 */

    const char *backend_host;     /* edge-peer: dial target. NULL if unused  */
    uint16_t    backend_port;
} relay_opts;

/* Build a relay around an already-connected (possibly still-connecting)
 * tunnel fd. Returns NULL on failure. */
relay *relay_new(int tunnel_fd, const relay_opts *opts);
void   relay_free(relay *r);

/* Run the event loop until the tunnel session dies or a signal asks to stop.
 * Returns 0 on clean teardown, non-zero on error. */
int    relay_run(relay *r);

/* Ask the loop to stop at the next iteration (async-signal-safe). */
void   relay_request_stop(void);

#endif /* MUX_RELAY_H */
