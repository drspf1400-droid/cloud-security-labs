FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bash \
    iputils-ping \
    procps \
    net-tools \
    iproute2 \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

RUN printf '#!/bin/bash\nexec "$@"\n' > /usr/local/bin/sudo && \
    chmod +x /usr/local/bin/sudo

RUN printf '#!/bin/bash\necho "inactive"\nexit 3\n' > /usr/local/bin/systemctl && \
    chmod +x /usr/local/bin/systemctl

WORKDIR /app
COPY . /app

RUN chmod +x checker.sh linux-security-audit.sh modules/*.sh

ENTRYPOINT ["./checker.sh"]
