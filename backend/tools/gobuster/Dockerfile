FROM golang:1.24-alpine AS build
FROM ubuntu:22.04

RUN apt update && apt install -y gobuster dirb && apt clean

ENTRYPOINT ["gobuster"]

RUN apk add --no-cache git
# Pin to a stable release.
RUN go install github.com/OJ/gobuster/v3@v3.7.0

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/gobuster /usr/local/bin/gobuster
ENTRYPOINT ["gobuster"]
