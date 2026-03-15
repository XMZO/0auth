FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
WORKDIR /src
ARG BUILDPLATFORM
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT

COPY go.mod ./
COPY main.go ./
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOARM_VALUE=""; \
    if [ "$TARGETARCH" = "arm" ] && [ -n "$TARGETVARIANT" ]; then GOARM_VALUE="${TARGETVARIANT#v}"; fi; \
    export GOARM="$GOARM_VALUE"; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/auth-proxy .

FROM scratch
COPY --from=build /out/auth-proxy /app/auth-proxy
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 8088
ENTRYPOINT ["/app/auth-proxy"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/auth-proxy", "-healthcheck"]
