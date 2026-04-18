FROM debian:stable-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends john ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work

ENTRYPOINT ["john"]
