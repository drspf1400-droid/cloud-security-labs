FROM ubuntu:22.04

RUN sed -i "s|http://archive.ubuntu.com/ubuntu/|http://us.archive.ubuntu.com/ubuntu/|g" /etc/apt/sources.list
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates && sed -i "s|http://us.archive.ubuntu.com/ubuntu/|https://us.archive.ubuntu.com/ubuntu/|g" /etc/apt/sources.list && sed -i "s|http://security.ubuntu.com/ubuntu/|https://security.ubuntu.com/ubuntu/|g" /etc/apt/sources.list && rm -rf /var/lib/apt/lists/*
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openssh-server \
    python3 \
    ufw \
    iproute2 \
    procps \
    net-tools \
    rsyslog \
    fail2ban \
    nginx \
    sudo && \
    rm -rf /var/lib/apt/lists/*

RUN touch /var/log/auth.log && chown syslog:adm /var/log/auth.log && chmod 640 /var/log/auth.log
RUN mkdir -p /run/sshd

# Intentionally insecure settings for the security lab
RUN echo 'root:LabRoot123!' | chpasswd && \
    sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN mkdir -p /var/www/html && \
    echo "Insecure VPS Security Lab" > /var/www/html/index.html

COPY nginx/default /etc/nginx/sites-available/default
EXPOSE 22 80 443

CMD ["/bin/bash", "-c", "mkdir -p /etc/nginx/ssl; if [ ! -f /etc/nginx/ssl/lab.crt ]; then openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/nginx/ssl/lab.key -out /etc/nginx/ssl/lab.crt -days 365 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 || exit 1; fi; rsyslogd && fail2ban-client -x start && /usr/sbin/sshd && nginx && exec python3 -m http.server 8080 --directory /var/www/html --bind 127.0.0.1"]
