FROM python:3.11-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates libglib2.0-0 libpango-1.0-0 libpangoft2-1.0-0 \
     libcairo2 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --no-cache-dir subdominator

ENTRYPOINT ["subdominator"]
