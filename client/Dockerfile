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

COPY --from=builder /client /app/client
COPY run.sh /

RUN chmod +x /run.sh

CMD ["/run.sh"]
