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

## worker node (behind NAT — no public IP / port-forward needed)
    EDGE_ADDR=<edge-ip>:5001 MUX_TOKEN=KEY \
      docker compose -f deploy/docker-compose.node.yml up -d --build

Verified end-to-end: client -> edge (Hetzner) -> mux tunnel over the internet ->
edge-peer (home NAT) -> 16 asyncio workers, balanced.
