FROM python:3.11-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
  && (pip install --no-cache-dir -r /opt/commix/requirements.txt 2>/dev/null || true)

ENTRYPOINT ["python3", "/opt/commix/commix.py"]
