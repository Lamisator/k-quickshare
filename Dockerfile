FROM golang:1.27-alpine AS build
WORKDIR /src

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=mod \
    go build -trimpath -ldflags="-s -w" -o /out/pyxis .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 pyxis \
 && adduser -S -G pyxis -u 10001 pyxis \
 && mkdir -p /data/files \
 && chown -R pyxis:pyxis /data
WORKDIR /app
COPY --from=build /out/pyxis /app/pyxis

ENV LISTEN_ADDR=:8080 \
    FILES_DIR=/data/files \
    COOKIE_SECURE=true

USER pyxis
EXPOSE 8080
ENTRYPOINT ["/app/pyxis"]
