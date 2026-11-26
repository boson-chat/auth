# Atheme 7.2.12 (Debian trixie package; ships transport/jsonrpc and xmlrpc).
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends atheme-services \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /mail && chown irc /data /mail
COPY atheme.conf /etc/atheme/atheme.conf
# auth = email: verification mail goes to this fake MTA, which keeps each
# message in /mail for the tests to read (docker exec).
COPY fake-mta.sh /usr/local/bin/fake-mta
USER irc
ENTRYPOINT ["/usr/bin/atheme-services", "-n", "-c", "/etc/atheme/atheme.conf", "-D", "/data", "-l", "/dev/stdout", "-p", "/data/atheme.pid"]
