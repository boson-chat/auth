# ngircd 27 (Debian trixie package): no SASL, so the IDENTIFY strategy.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ngircd \
    && rm -rf /var/lib/apt/lists/*
COPY ngircd.conf /etc/ngircd/ngircd.conf
USER irc
ENTRYPOINT ["/usr/sbin/ngircd", "--nodaemon", "--config", "/etc/ngircd/ngircd.conf"]
