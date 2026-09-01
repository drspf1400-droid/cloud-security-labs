FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openssh-server \
    python3 \
    ufw \
    iproute2 \
    procps \
    net-tools \
    sudo && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

# Intentionally insecure settings for the security lab
RUN echo 'root:LabRoot123!' | chpasswd && \
    sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN mkdir -p /var/www/html && \
    echo "Insecure VPS Security Lab" > /var/www/html/index.html

EXPOSE 22 8080

CMD ["/bin/bash", "-c", "/usr/sbin/sshd && python3 -m http.server 8080 --directory /var/www/html --bind 0.0.0.0"]
