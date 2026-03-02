# ── Stage 1: Build React frontend ───────────────────────────────────
FROM node:22-slim AS frontend-build
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ .
RUN npm run build

# ── Stage 2: Build Rust backend (with embedded frontend) ────────────
FROM rust:1.85-slim AS backend-build
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY --from=frontend-build /app/dashboard/dist dashboard/dist
RUN cargo build --release --bin fishnet --features embed-dashboard

# ── Stage 3: Runtime (single binary, no extra files) ────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash fishnet

WORKDIR /home/fishnet

COPY --from=backend-build /app/target/release/fishnet /usr/local/bin/fishnet

RUN mkdir -p /var/lib/fishnet /home/fishnet && chown -R fishnet:fishnet /var/lib/fishnet /home/fishnet

USER fishnet

ENV FISHNET_HOST=0.0.0.0
ENV FISHNET_DATA_DIR=/var/lib/fishnet
EXPOSE 8473

CMD ["fishnet"]
