FROM golang:1.27-alpine AS build
WORKDIR /src

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=mod \
    go build -trimpath -ldflags="-s -w" -o /out/fileshare .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 kshare \
 && adduser -S -G kshare -u 10001 kshare \
 && mkdir -p /data/files \
 && chown -R kshare:kshare /data
WORKDIR /app
COPY --from=build /out/fileshare /app/fileshare

ENV LISTEN_ADDR=:8080 \
    FILES_DIR=/data/files \
    COOKIE_SECURE=true

USER kshare
EXPOSE 8080
ENTRYPOINT ["/app/fileshare"]
