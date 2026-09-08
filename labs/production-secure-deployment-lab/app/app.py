import os
import time
import psycopg2
from flask import Flask, jsonify, request
from prometheus_client import Counter, Histogram, CollectorRegistry, multiprocess, generate_latest


app = Flask(__name__)

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
)

@app.before_request
def start_request_timer():
    request._prom_start_time = time.perf_counter()

@app.after_request
def record_request_metrics(response):
    if request.path != "/metrics":
        endpoint = request.endpoint or "unknown"

        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=endpoint,
            status=response.status_code,
        ).inc()

        start_time = getattr(request, "_prom_start_time", None)
        if start_time is not None:
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=endpoint,
            ).observe(time.perf_counter() - start_time)

    return response

def get_db_connection():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )

@app.get("/")
def home():
    return jsonify(
        service="production-secure-deployment-lab",
        status="running"
    )

@app.get("/health")
def health():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.close()
        conn.close()

        return jsonify(
            status="healthy",
            database="connected"
        ), 200

    except Exception:
        return jsonify(
            status="unhealthy",
            database="unavailable"
        ), 503

@app.get("/metrics")
def metrics():
    database_up = 0

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.close()
        conn.close()
        database_up = 1
    except Exception:
        database_up = 0

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)

    prometheus_metrics = generate_latest(registry).decode("utf-8")

    custom_metrics = (
        "# HELP app_up Whether the application is running.\n"
        "# TYPE app_up gauge\n"
        "app_up 1\n"
        "# HELP database_up Whether PostgreSQL is reachable.\n"
        "# TYPE database_up gauge\n"
        f"database_up {database_up}\n"
    )

    return custom_metrics + prometheus_metrics, 200, {
        "Content-Type": "text/plain; version=0.0.4; charset=utf-8"
    }
