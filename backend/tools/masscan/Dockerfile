FROM debian:stable-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends masscan ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["masscan"]
