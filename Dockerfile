# 1. This tells docker to use the Rust official image
FROM rust:1-bullseye as builder

WORKDIR /usr/src/airshare

RUN apt-get update && apt-get install -y musl-tools protobuf-compiler

# 2. Copy the files in your machine to the Docker image
COPY ./src ./src
COPY ./ProtobufSource ./ProtobufSource
COPY ./Cargo.toml ./Cargo.toml
COPY ./icons ./icons
COPY ./ui ./ui
COPY ./tauri.conf.json ./tauri.conf.json
COPY ./build.rs ./build.rs

## Install target platform (Cross-Compilation) --> Needed for Alpine
RUN rustup target add x86_64-unknown-linux-musl

# Build your program for release
RUN cargo build --target x86_64-unknown-linux-musl --profile release --features docker

RUN file /usr/src/airshare/target/x86_64-unknown-linux-musl/release/airshare

FROM alpine:latest

COPY --from=builder /usr/src/airshare/target/x86_64-unknown-linux-musl/release/airshare /bin/airshare

ENTRYPOINT ["/bin/airshare"]