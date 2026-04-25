FROM kalilinux/kali-rolling:latest

RUN apt-get update \
  && apt-get install -y --no-install-recommends exploitdb ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["searchsploit"]
