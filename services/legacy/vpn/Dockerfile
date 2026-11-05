FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server tzdata procps coreutils \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd
COPY legacy/vpn/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
