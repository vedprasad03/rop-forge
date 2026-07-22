FROM --platform=linux/amd64 python:3.12-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gdb \
    pkg-config \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /workspace
