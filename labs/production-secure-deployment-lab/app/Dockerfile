FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
ARG PIP_INDEX_URL=https://pypi.org/simple

COPY requirements.txt .

RUN pip install --no-cache-dir --index-url "$PIP_INDEX_URL" -r requirements.txt \
    && useradd --create-home --shell /usr/sbin/nologin appuser

COPY app.py .

RUN mkdir -p /tmp/prometheus_multiproc     && chown -R appuser:appuser /app /tmp/prometheus_multiproc

USER appuser

ENV PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus_multiproc

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
