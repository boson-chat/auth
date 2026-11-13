# boson auth service. Cross-compiles on the build host (no QEMU for Go).
FROM --platform=$BUILDPLATFORM golang:1.27 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/auth ./cmd

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=builder --chown=65532:65532 /out/auth .

ARG VERSION=dev
ENV VERSION=$VERSION ENV=production

# 8080: public API (behind the reverse proxy). 8081: internal API + /metrics (never publish).
EXPOSE 8080 8081
USER 65532:65532
ENTRYPOINT ["./auth"]
CMD ["serve"]
