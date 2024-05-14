# The images specified in this Dockerfile are multi-platform images. Digests point to the index
FROM rust:1.78.0-slim-bookworm@sha256:517c6272b328bc51c87e099ef4adfbc7ab4558af2d757e8d423c7c3f1cbbf9d5 as builder

WORKDIR /build

COPY . .

# Could optimize this build with cargo-chef https://github.com/LukeMathWalker/cargo-chef
RUN cargo build --release

FROM debian:bookworm-20240513-slim@sha256:804194b909ef23fb995d9412c9378fb3505fe2427b70f3cc425339e48a828fca

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/tail_sts .

ENTRYPOINT [ "./tail_sts" ]
