/* edge-peer stream router: aggregates one upstream edge tunnel and a pool of
 * worker tunnels, SWRR-balancing each inbound stream onto a worker and
 * splicing stream<->stream with flow-control-coupled backpressure. */
#ifndef EP_ROUTER_H
#define EP_ROUTER_H

#include <stdint.h>

typedef struct {
    const char  *edge_addr;     /* upstream edge to dial ("host:port")        */
    const char **workers;       /* worker addresses ("host:port" or unix path)*/
    int          nworkers;
    const char  *token;
    const char  *peer_id;
    uint32_t     init_window;
    uint32_t     session_window;
    uint32_t     heartbeat_ms;
} ep_config;

/* Run the router until stopped. Returns 0 on clean exit. */
int  ep_run(const ep_config *cfg);
void ep_request_stop(void);

#endif /* EP_ROUTER_H */
