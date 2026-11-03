# Стенд e2e: Debian 13 (trixie) с OpenSSH — цель проверки по учётной записи.
# Только для изолированной сети e2e-lab (internal), наружу не публикуется.
FROM debian:trixie
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server netcat-openbsd procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash audit
# Пароль учётки стенда задаётся при запуске (E2E_SSH_PASSWORD), не в образе.
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["sh", "/entrypoint.sh"]
