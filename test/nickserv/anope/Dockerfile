# Anope 2.1 built from a pinned release tag (no official image ships 2.1).
# Test fixture only: see test/nickserv/README.md.
FROM debian:trixie-slim AS build
ARG ANOPE_VERSION=2.1.28
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl cmake g++ make libgnutls28-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSL "https://github.com/anope/anope/archive/refs/tags/${ANOPE_VERSION}.tar.gz" | tar xz --strip-components=1
RUN cmake -B build -DINSTDIR=/anope -DCMAKE_BUILD_TYPE=RELEASE -DDEFUMASK=077 . \
    && make -C build -j"$(nproc)" install

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgnutls30t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* && useradd -r -u 10000 anope
COPY --from=build /anope /anope
COPY anope.conf /anope/conf/anope.conf
RUN sed -e 's/registration = "code"/registration = "none"/' \
        -e 's/regdelay = 15m/regdelay = 0/' \
        -e 's/minpasslen = 10/minpasslen = 5/' \
        /anope/conf/nickserv.example.conf > /anope/conf/nickserv.conf \
    && grep -q 'registration = "none"' /anope/conf/nickserv.conf && touch /anope/conf/motd.txt
RUN chown -R anope /anope/data /anope/logs 2>/dev/null; mkdir -p /anope/data /anope/logs && chown -R anope /anope/data /anope/logs
USER anope
WORKDIR /anope
ENTRYPOINT ["/anope/bin/anope", "--nofork"]
