# Python backend image: builds the muxpeer extension from the repo sources and
# runs N worker replicas under supervisord, each on its own unix socket.
#
# Build context must be the REPO ROOT (the extension needs the C sources):
#   docker build -f examples/python-app/Dockerfile -t mux-app .

# ---- build the muxpeer extension (clang, matches the project toolchain) ----
FROM python:3.12-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir setuptools \
    && cd python && CC=clang python setup.py build_ext --inplace

# ---- runtime: python + supervisord + the app ----
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends supervisor \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /src/python/muxpeer*.so /app/
COPY examples/python-app/app.py /app/app.py
COPY examples/python-app/supervisord.conf /app/supervisord.conf
ENV PYTHONPATH=/app
RUN mkdir -p /sockets
CMD ["supervisord", "-c", "/app/supervisord.conf"]
