FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /server /app/server

# Create data directory
RUN mkdir -p /data

EXPOSE 80 7777

CMD ["/app/server"]
