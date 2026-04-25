FROM golang:1.22-alpine AS builder

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx

ENTRYPOINT ["httpx"]
