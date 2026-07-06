# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

ARG TARGETARCH
ARG ZIG_VERSION=0.13.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
    && mkdir -p /opt/zig \
    && tar -xf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /tmp/zig.tar.xz

ENV PATH="/opt/zig:${PATH}"

RUN cargo install cargo-zigbuild --locked

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) rust_target="x86_64-unknown-linux-musl" ;; \
        arm64) rust_target="aarch64-unknown-linux-musl" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}; supported: amd64, arm64" >&2; exit 1 ;; \
    esac; \
    rustup target add "${rust_target}"; \
    cargo zigbuild --bin iwan-client-oidc --target "${rust_target}" --release; \
    mkdir -p /out; \
    cp "target/${rust_target}/release/iwan-client-oidc" /out/iwan-client-oidc

FROM debian:bookworm-slim AS proxy-builder

ARG THREEPROXY_VERSION=0.9.5

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -fsSL "https://github.com/3proxy/3proxy/archive/refs/tags/${THREEPROXY_VERSION}.tar.gz" -o /tmp/3proxy.tar.gz \
    && tar -xf /tmp/3proxy.tar.gz -C /src --strip-components=1 \
    && make -f Makefile.Linux \
    && mkdir -p /out \
    && cp bin/3proxy /out/3proxy

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/iwan-client-oidc /usr/local/bin/iwan-client-oidc
COPY --from=proxy-builder /out/3proxy /usr/local/bin/3proxy
COPY docker/3proxy.cfg /etc/3proxy/3proxy.cfg
COPY docker/iwan-entrypoint.sh /usr/local/bin/iwan-entrypoint
COPY docker/iwan-healthcheck.sh /usr/local/bin/iwan-healthcheck

RUN chmod +x /usr/local/bin/iwan-client-oidc /usr/local/bin/3proxy /usr/local/bin/iwan-entrypoint /usr/local/bin/iwan-healthcheck \
    && mkdir -p /config

VOLUME ["/config"]
EXPOSE 1080 8888
HEALTHCHECK --interval=150s --timeout=5s --start-period=90s --retries=3 CMD iwan-healthcheck

ENTRYPOINT ["iwan-entrypoint"]
CMD ["auto"]
