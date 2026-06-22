# Running mux across machines

## edge (public VPS)
Run the edge on a **custom Docker network**, not the default bridge. Hardened
hosts (Dokploy/Swarm) often disable inter-container communication (ICC) on the
default `bridge`, which RSTs the uplink within ~2ms — the tunnel connects but
never authenticates ("uplink connected" -> "uplink gone", no "tunnel
authenticated"). A custom network is not ICC-restricted.

    docker network create muxnet
    docker run -d --name edge --network muxnet --restart unless-stopped \
      --ulimit nofile=1048576:1048576 \
      --sysctl net.core.somaxconn=65535 \
      --sysctl net.ipv4.tcp_max_syn_backlog=65535 \
      -p 5000:5000 -p 5001:5001 \
      gig4ch4d/edge:latest --accept-port 5000 --mux-port 5001 --token KEY

- `:5000` public (clients), `:5001` uplink (edge-peer dials in).
- The sysctls let the kernel queue large SYN bursts (backlog is 65535 in-image).

## Scaling the edge ingress (two independent axes)

The edge event loop is single-threaded, so one process saturates one core. Spread
ingress two ways — and combine them:

**1. All cores on one VPS — `--procs K`.** The edge master forks K workers that
share `--accept-port` via `SO_REUSEPORT` (kernel spreads client SYNs, one accept
queue per worker) and each listens on its own uplink port `--mux-port + i`:

    docker run -d --name edge --network muxnet --restart unless-stopped \
      --ulimit nofile=1048576:1048576 \
      --sysctl net.core.somaxconn=65535 \
      --sysctl net.ipv4.tcp_max_syn_backlog=65535 \
      -p 5000:5000 -p 5001-5004:5001-5004 \
      gig4ch4d/edge:latest --accept-port 5000 --mux-port 5001 --procs 4 --token KEY

  Uplinks land on `:5001..:5004`. The edge-peer dials all of them.

**2. Many VPSes — more edges.** Run an edge on each VPS (each on its own muxnet).

The edge-peer aggregates every uplink — pass `--edge HOST:PORT` (alias `--connect`)
once per uplink port, across all procs and all VPSes:

    edge-peer --edge VPS_A:5001 --edge VPS_A:5002 --edge VPS_A:5003 --edge VPS_A:5004 \
              --edge VPS_B:5001 --edge VPS_B:5002 \
              --worker /run/app_00.sock --worker /run/app_01.sock ... --token KEY

Each inbound stream from any edge is SWRR-balanced onto the shared worker pool; if
an edge dies its in-flight streams are reset downstream and the rest keep serving.

## worker node (behind NAT — no public IP / port-forward needed)
    EDGE_ADDR=<edge-ip>:5001 MUX_TOKEN=KEY \
      docker compose -f deploy/docker-compose.node.yml up -d --build

(For multi-edge, set the edge-peer's `--edge` list in the compose/launch command.)

Verified end-to-end: client -> edge (Hetzner) -> mux tunnel over the internet ->
edge-peer (home NAT) -> 16 asyncio workers, balanced. Multi-edge + `--procs`
smoke-tested locally: 2 edge procs, both uplinks up, traffic balanced 1:3.
