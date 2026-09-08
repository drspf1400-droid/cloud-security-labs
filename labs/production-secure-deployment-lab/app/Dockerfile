FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
ARG PIP_INDEX_URL=https://pypi.org/simple

COPY requirements.txt .

RUN pip install --no-cache-dir --index-url "$PIP_INDEX_URL" -r requirements.txt \
    && useradd --create-home --shell /usr/sbin/nologin appuser

COPY app.py .

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
