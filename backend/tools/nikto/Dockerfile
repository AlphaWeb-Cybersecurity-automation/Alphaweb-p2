FROM debian:stable-slim
FROM ubuntu:22.04

RUN apt update && apt install -y \
    nikto \
    libjson-perl \
    libxml-writer-perl \
    && apt clean

ENTRYPOINT ["nikto"]

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwww-perl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 https://github.com/sullo/nikto.git

WORKDIR /opt/nikto/program
ENTRYPOINT ["perl", "nikto.pl"]
