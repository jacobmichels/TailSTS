# The images specified in this Dockerfile are multi-platform images. Digests point to the index
FROM rust:1.77.2-slim-bookworm@sha256:e9cd563b30c358b862272a5bb38fd72347d357f1b0a74ab829d80f1e81e879bb as builder

WORKDIR /build

COPY . .

# Could optimize this build with cargo-chef https://github.com/LukeMathWalker/cargo-chef
RUN cargo build --release

FROM debian:bookworm-20240423-slim@sha256:155280b00ee0133250f7159b567a07d7cd03b1645714c3a7458b2287b0ca83cb

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/tail_sts .

ENTRYPOINT [ "./tail_sts" ]
