FROM rust:1.87 AS builder

WORKDIR /usr/src/app
COPY src/ src/
COPY Cargo.toml Cargo.toml

RUN cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/cm-game-auth /usr/local/bin/cm-game-auth

CMD ["cm-game-auth"]