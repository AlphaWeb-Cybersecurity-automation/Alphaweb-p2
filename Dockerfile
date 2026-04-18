FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 8000

# This orchestrator uses Docker (CLI) to run the tool containers, so bind-mount
# the host Docker socket in docker-compose.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

