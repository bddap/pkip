FROM rust:1.66 as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM debian:buster-slim
COPY --from=builder /usr/src/app/target/release/directory-server /usr/local/bin/directory-server
CMD ["directory-server"]
