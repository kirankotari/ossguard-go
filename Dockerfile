FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o ossguard ./cmd/ossguard

FROM alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/kirankotari/ossguard-go"
LABEL org.opencontainers.image.description="One CLI to guard any OSS project with OpenSSF security best practices"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache git && \
    adduser -D -h /home/ossguard ossguard

COPY --from=builder /build/ossguard /usr/local/bin/ossguard

USER ossguard
WORKDIR /project

ENTRYPOINT ["ossguard"]
CMD ["--help"]
