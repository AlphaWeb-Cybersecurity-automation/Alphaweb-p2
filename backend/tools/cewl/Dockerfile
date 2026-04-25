FROM ruby:3.2-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && gem install cewl --no-document

ENTRYPOINT ["cewl"]
