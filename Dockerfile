FROM golang:1.25 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/bin/auth ./cmd

FROM alpine:3.20
LABEL org.opencontainers.image.source=https://github.com/Daniel3579/auth-service
WORKDIR /app
COPY --from=builder /app/bin/auth /app/auth
CMD ["/app/auth"]