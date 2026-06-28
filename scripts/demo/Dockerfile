FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Tooling for diff acquisition + source-function analysis (the default demo
# path) plus the curl build dependencies needed for the optional --compile /
# --target-build steps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    ca-certificates \
    file \
    g++ \
    gcc \
    git \
    libssl-dev \
    libtool \
    make \
    perl \
    pkg-config \
    python3 \
    python3-dateutil \
    python3-packaging \
    python3-requests \
    universal-ctags \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /artifact
COPY . /artifact

# Default: run the 5 curl CVEs through diff acquisition + source-function
# analysis (no compilation). Override the command to add heavier stages, e.g.:
#   docker run --rm <image> --compile
#   docker run --rm <image> --target-build
#
# NOTE: --bindiff runs ghidriff as a sibling Docker container
# (ghcr.io/clearbluejar/ghidriff:0.5.2), so it is best run on the host or with
# the Docker socket mounted (-v /var/run/docker.sock:/var/run/docker.sock) and a
# docker client available; it is intentionally not baked into this image.
ENTRYPOINT ["python3", "scripts/demo/run_demo.py", "--output", "/demo-output"]
