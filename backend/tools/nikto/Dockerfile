FROM debian:stable-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwww-perl \
    libjson-perl \
    libxml-writer-perl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 https://github.com/sullo/nikto.git

WORKDIR /opt/nikto/program
ENTRYPOINT ["perl", "nikto.pl"]
