FROM rust:1.82 AS builder

WORKDIR /usr/src/app
COPY src/ src/
COPY Cargo.toml Cargo.toml

RUN cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/cm-api-rs /usr/local/bin/cm-api-rs

CMD ["cm-api-rs"]