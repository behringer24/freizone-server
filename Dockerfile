# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
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
