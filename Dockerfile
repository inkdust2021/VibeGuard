# syntax=docker/dockerfile:1

FROM golang:1.24 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VG_TAG=dev
ARG VG_COMMIT=unknown
ARG VG_BUILD_DATE=unknown
ARG VG_BUILD_TAGS=
RUN set -eu; \
  tags=""; \
  if [ -n "${VG_BUILD_TAGS}" ]; then tags="-tags ${VG_BUILD_TAGS}"; fi; \
  ldflags="-s -w -X github.com/inkdust2021/vibeguard/internal/version.Version=${VG_TAG} -X github.com/inkdust2021/vibeguard/internal/version.GitCommit=${VG_COMMIT} -X github.com/inkdust2021/vibeguard/internal/version.BuildDate=${VG_BUILD_DATE}"; \
  CGO_ENABLED=0 go build -trimpath -buildvcs=false ${tags} -ldflags "${ldflags}" -o /out/vibeguard ./cmd/vibeguard

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && update-ca-certificates

WORKDIR /root
ENV HOME=/root

COPY --from=builder /out/vibeguard /usr/local/bin/vibeguard
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 28657

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["start", "--foreground"]
