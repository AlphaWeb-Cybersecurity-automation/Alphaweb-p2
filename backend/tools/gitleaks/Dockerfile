FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git \
  && GOBIN=/usr/local/bin go install github.com/zricethezav/gitleaks/v8@latest

FROM alpine:3.21

COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks

RUN apk add --no-cache ca-certificates git

ENTRYPOINT ["gitleaks"]
