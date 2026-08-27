# syntax=docker/dockerfile:1

# Pinned to an exact patch, not the floating 1.26-alpine tag. Two reasons, both
# learned the hard way on the 0.25.0 update: a floating tag makes the build
# non-reproducible while *also* not keeping itself current (Docker reuses
# whatever sits in the local cache unless the caller passes --pull), and the
# official Go image sets GOTOOLCHAIN=local, so it never fetches a newer
# toolchain on its own -- a cached image older than go.mod's `go` line fails
# the build outright rather than adapting.
#
# This must stay >= the `go` line in go.mod. Raising that line without raising
# this one is what breaks the build, so move both together. Bump this on Go
# patch releases to pick up standard-library security fixes; `govulncheck ./...`
# reports when that is due.
FROM golang:1.26.7-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/freizone-server ./cmd/server

# distroless/static provides CA certificates (needed for autocert's outbound
# ACME requests) and nothing else -- the binary is fully static (CGO_ENABLED=0,
# pure-Go SQLite driver), so no libc is required.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/freizone-server /freizone-server

ENV FREIZONE_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 80 443

ENTRYPOINT ["/freizone-server"]
