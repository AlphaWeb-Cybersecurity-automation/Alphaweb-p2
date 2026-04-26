FROM golang:1.24-alpine AS build

RUN apk add --no-cache git
RUN go install github.com/OJ/gobuster/v3@v3.7.0

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/gobuster /usr/local/bin/gobuster

# Include a small built-in wordlist at a predictable path
RUN mkdir -p /wordlists && printf 'admin\nlogin\napi\ntest\nuploads\nstatic\nimages\ncss\njs\nassets\n.env\ndashboard\nbackup\nconfig\nregister\nsearch\ncontact\nabout\nhome\nblog\nwp-admin\nwp-login.php\nwp-content\nxmlrpc.php\nrobots.txt\nsitemap.xml\n' > /wordlists/common.txt

ENTRYPOINT ["gobuster"]
