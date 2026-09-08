import os
import psycopg2
from flask import Flask, jsonify

app = Flask(__name__)

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

    payload = (
        "# HELP app_up Whether the application is running.\n"
        "# TYPE app_up gauge\n"
        "app_up 1\n"
        "# HELP database_up Whether PostgreSQL is reachable.\n"
        "# TYPE database_up gauge\n"
        f"database_up {database_up}\n"
    )

    return payload, 200, {
        "Content-Type": "text/plain; version=0.0.4; charset=utf-8"
    }
