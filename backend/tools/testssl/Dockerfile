FROM debian:stable-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     bash curl dnsutils ca-certificates openssl bsdmainutils procps git \
  && rm -rf /var/lib/apt/lists/* \
  && git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
  && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

WORKDIR /opt/testssl
ENTRYPOINT ["testssl.sh"]
