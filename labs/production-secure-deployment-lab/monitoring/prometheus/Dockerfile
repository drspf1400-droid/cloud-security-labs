FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends prometheus \
    && rm -rf /var/lib/apt/lists/*

COPY prometheus.yml /etc/prometheus/prometheus.yml

RUN mkdir -p /prometheus \
    && chown -R prometheus:prometheus /prometheus

USER prometheus

EXPOSE 9090

CMD ["/usr/bin/prometheus", \
     "--config.file=/etc/prometheus/prometheus.yml", \
     "--storage.tsdb.path=/prometheus", \
     "--web.listen-address=0.0.0.0:9090"]
