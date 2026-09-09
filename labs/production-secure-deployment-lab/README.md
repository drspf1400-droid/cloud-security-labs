# Production Secure Deployment Lab

A production-style DevOps and security lab demonstrating secure containerized deployment, HTTPS reverse proxying, database isolation, monitoring, backup/restore validation, and CI runtime testing.

## Architecture

```text
Client -> HTTPS -> Nginx -> Flask/Gunicorn -> PostgreSQL
                         |
                         +-> /metrics -> Prometheus -> Grafana
```

## Features

- Docker Compose deployment
- Flask served by Gunicorn
- Non-root application user
- PostgreSQL health checks
- Internal backend network
- App and DB not exposed directly to the host
- Nginx reverse proxy with HTTP -> HTTPS redirect
- Local TLS support
- Environment-based secrets
- PostgreSQL backup and restore validation
- Prometheus metrics
- Provisioned Grafana datasource and dashboard
- Application and database health monitoring
- Request count, error rate, and response-time metrics
- GitHub Actions validation
- Runtime HTTPS smoke test

## Security Design

Only Nginx exposes application ports:

```text
127.0.0.1:8085 -> HTTP
127.0.0.1:8443 -> HTTPS
```

Sensitive files are excluded from Git:

```text
.env
backups/
nginx/certs/
__pycache__/
*.pyc
```

## Endpoints

Health:

```text
GET /health
```

Example:

```json
{"database":"connected","status":"healthy"}
```

Metrics:

```text
GET /metrics
```

Key metrics:

```text
app_up
database_up
http_requests_total
http_request_duration_seconds_count
http_request_duration_seconds_sum
```

## Monitoring

Grafana is provisioned with Prometheus and the **Production Secure Deployment** dashboard.

Dashboard panels:

- Application Status
- Database Status
- Total Requests
- Error Rate
- Average Response Time

## Backup and Restore

A PostgreSQL backup was created with `pg_dump`, restored into a separate test database, and validated by querying the restored data.

## CI Pipeline

GitHub Actions performs:

```text
Python syntax validation
-> Docker Compose validation
-> Grafana JSON validation
-> Application image build
-> Temporary TLS certificate generation
-> Runtime HTTPS smoke test
```

The smoke test validates:

```text
HTTPS -> Nginx -> Flask/Gunicorn -> PostgreSQL -> /health
```

## Setup

Create the environment file:

```bash
cp .env.example .env
```

Set secure values for:

```text
POSTGRES_DB
POSTGRES_USER
POSTGRES_PASSWORD
GRAFANA_ADMIN_USER
GRAFANA_ADMIN_PASSWORD
```

Generate a local self-signed TLS certificate:

```bash
mkdir -p nginx/certs
openssl req -x509 -nodes -newkey rsa:2048 -keyout nginx/certs/lab.key -out nginx/certs/lab.crt -days 365 -subj "/CN=localhost"
chmod 600 nginx/certs/lab.key
```

Start the stack:

```bash
docker compose up -d
docker compose ps
```

Health test:

```bash
curl -k https://127.0.0.1:8443/health
```

Prometheus: `http://127.0.0.1:9090`

Grafana: `http://127.0.0.1:3000`

## Technology Stack

Linux, Docker, Docker Compose, Python, Flask, Gunicorn, PostgreSQL, Nginx, TLS/HTTPS, Prometheus, Grafana, Git, and GitHub Actions.

## Purpose

This is an educational production-style DevOps and security portfolio project. It demonstrates practical deployment, network isolation, observability, database protection, backup validation, and CI runtime testing in one working environment.
