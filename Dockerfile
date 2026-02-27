# syntax=docker/dockerfile:1

FROM golang:1.24 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/vibeguard ./cmd/vibeguard

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && update-ca-certificates

WORKDIR /root
ENV HOME=/root

COPY --from=builder /out/vibeguard /usr/local/bin/vibeguard
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 28657

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["start", "--foreground"]
