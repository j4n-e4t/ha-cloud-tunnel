FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 tunnel && \
    adduser -u 1000 -G tunnel -s /bin/sh -D tunnel

WORKDIR /app
COPY --from=builder /server /app/server

# Create data directory with proper ownership
RUN mkdir -p /data && chown tunnel:tunnel /data

USER tunnel

EXPOSE 80 7777

CMD ["/app/server"]
