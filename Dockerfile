FROM golang:1.22-alpine AS build
WORKDIR /src

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=mod \
    go build -trimpath -ldflags="-s -w" -o /out/fileshare .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/fileshare /app/fileshare

ENV LISTEN_ADDR=:8080 \
    FILES_DIR=/data/files \
    COOKIE_SECURE=true

EXPOSE 8080
ENTRYPOINT ["/app/fileshare"]
