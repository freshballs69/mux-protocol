# C daemons image: edge, edge-peer, http_worker. (The Python worker app has its
# own image under examples/python-app.) On Linux the relay uses epoll.
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build clang libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang \
    && cmake --build build --target edge edge-peer http_worker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/edge        /usr/local/bin/edge
COPY --from=builder /src/build/edge-peer   /usr/local/bin/edge-peer
COPY --from=builder /src/build/http_worker /usr/local/bin/http_worker
RUN mkdir -p /sockets
CMD ["edge", "--help"]
