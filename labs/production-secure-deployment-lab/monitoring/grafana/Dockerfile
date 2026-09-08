FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL \
       https://dl.grafana.com/grafana/release/13.2.1/grafana_13.2.1_33191028959_linux_amd64.deb \
       -o /tmp/grafana.deb \
    && apt-get install -y /tmp/grafana.deb \
    && rm -f /tmp/grafana.deb \
    && rm -rf /var/lib/apt/lists/* \
    && test -x /usr/share/grafana/bin/grafana

USER grafana

EXPOSE 3000

ENTRYPOINT ["/usr/share/grafana/bin/grafana"]

CMD ["server", \
     "--homepath=/usr/share/grafana", \
     "--config=/etc/grafana/grafana.ini"]
