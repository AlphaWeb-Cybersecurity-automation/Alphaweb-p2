FROM ruby:3.2-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     build-essential ca-certificates git \
  && rm -rf /var/lib/apt/lists/* \
  && git clone --depth 1 https://github.com/digininja/CeWL.git /opt/cewl \
  && cd /opt/cewl \
  && gem install bundler --no-document \
  && bundle config set without 'development' \
  && bundle install

WORKDIR /opt/cewl
ENTRYPOINT ["ruby", "cewl.rb"]
