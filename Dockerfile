# The images specified in this Dockerfile are multi-platform images. Digests point to the index
FROM rust:1.77.2-slim-bookworm@sha256:badf412ccb1e2ece18376a1e8e4a7754a2ad126cc4048072d6ba659fa6cbdcb6 as builder

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
