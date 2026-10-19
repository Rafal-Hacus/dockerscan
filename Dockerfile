# Build stage: compile dockerscan and rebuild the CVE database from its parts
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/dockerscan ./cmd/dockerscan

# The database is stored as <25MB parts; join, verify and decompress it
RUN cat data/latest.db.gz.part-* > /tmp/latest.db.gz \
 && echo "$(cat data/latest.db.gz.sha256)  /tmp/latest.db.gz" | sha256sum -c - \
 && gunzip -c /tmp/latest.db.gz > /out/cve-db.sqlite

# Runtime stage
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
# Some platforms start containers without $HOME; the CVE database lives in it
ENV HOME=/root

COPY --from=build /out/dockerscan /usr/local/bin/dockerscan
COPY --from=build /out/cve-db.sqlite /root/.dockerscan/cve-db.sqlite

# Image to scan. Scanning requires access to a Docker daemon, e.g. a mounted
# /var/run/docker.sock or DOCKER_HOST pointing at one.
ENV SCAN_IMAGE=nginx:latest

EXPOSE 80 443
ENTRYPOINT ["/bin/sh", "-c", "exec dockerscan --serve \"$SCAN_IMAGE\""]
