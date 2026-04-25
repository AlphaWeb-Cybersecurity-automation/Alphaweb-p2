FROM debian:stable-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     bash curl dnsutils ca-certificates openssl bsdmainutils procps \
  && rm -rf /var/lib/apt/lists/* \
  && curl -fsSL https://testssl.sh/testssl.sh -o /usr/local/bin/testssl.sh \
  && chmod +x /usr/local/bin/testssl.sh

ENTRYPOINT ["testssl.sh"]
