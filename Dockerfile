# The images specified in this Dockerfile are multi-platform images. Digests point to the index
FROM rust:1.78.0-slim-bookworm@sha256:57a59f2a7fbdd03130b1327ec642091f4fcad442e80d876c39d90ee4f56602c3 as builder

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
