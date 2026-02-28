FROM rust:1.93.1 AS builder
RUN apt-get update && apt-get install -y linux-perf
RUN cargo install flamegraph
RUN echo "kernel.perf_event_paranoid = -1" >>/etc/sysctl.conf
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt update && apt install iputils-ping tcpdump -y
RUN apt-get update && apt-get install -y nftables iproute2 watch conntrack
# && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/vpn /usr/local/bin/vpn
COPY users.txt /app
COPY server.priv /app
COPY nftables.conf /etc/nftables.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
# Если приложению нужны конфиги — скопируйте их или смонтируйте том
# CMD ["vpn", "listen", "/app/users.txt", "/app/server.priv", "8080", "10.0.0.1", "255.255.255.0"]