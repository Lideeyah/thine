# The hosted judge path: thine-web in demo mode. The relayer key arrives as
# environment at deploy time and is never part of this image or repository.
FROM rust:1.100-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p thine-web

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/thine-web /usr/local/bin/thine-web
# Sessions are in memory and the ledger directory is ephemeral by design: a
# restart forgets in-flight sessions and a visitor starts a fresh one.
CMD ["thine-web", "--demo", "--send-rpc", "https://rpc.testnet.fastnear.com"]
