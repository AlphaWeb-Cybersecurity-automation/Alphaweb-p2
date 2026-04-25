FROM ruby:3.2-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential libcurl4-openssl-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && gem install wpscan --no-document

ENTRYPOINT ["wpscan"]
