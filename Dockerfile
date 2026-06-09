FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin gitgate-proxy --bin gitgate-cert

FROM alpine:3.20
RUN apk add --no-cache ca-certificates su-exec
RUN adduser -S -u 1000 gitgate
COPY --from=builder /src/target/release/gitgate-proxy /usr/local/bin/
COPY --from=builder /src/target/release/gitgate-cert /usr/local/bin/
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 7443
ENTRYPOINT ["entrypoint.sh"]
