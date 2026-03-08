ARG BUILD_FROM=ghcr.io/hassio-addons/base:15.0.8

# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /client .

# Runtime stage
FROM ${BUILD_FROM}

RUN apk --no-cache add ca-certificates

# Create non-root user (may already exist in hassio-addons base)
RUN addgroup -g 1000 tunnel 2>/dev/null || true && \
    adduser -u 1000 -G tunnel -s /bin/sh -D tunnel 2>/dev/null || true

COPY --from=builder /client /app/client
COPY run.sh /

RUN chmod +x /run.sh

# Note: Home Assistant add-ons may need root for bashio, so this is conditional
# For standalone use, uncomment: USER tunnel

CMD ["/run.sh"]
