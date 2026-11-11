# SSO — the Go build. Templates and assets are embedded in the binary.
FROM docker.io/library/golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/sso .

FROM docker.io/library/alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/sso /app/sso
ENV SSO_LISTEN=0.0.0.0:3550
EXPOSE 3550
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:3550/healthz >/dev/null || exit 1
ENTRYPOINT ["/app/sso"]
