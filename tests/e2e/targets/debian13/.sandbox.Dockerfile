# Стенд e2e: Debian 13 (trixie) с OpenSSH — цель проверки по учётной записи.
# Только для изолированной сети e2e-lab (internal), наружу не публикуется.
FROM debian:trixie
COPY .sandbox-ca.crt /usr/local/share/sandbox-ca.crt
ENV HTTPS_PROXY=http://127.0.0.1:33591 https_proxy=http://127.0.0.1:33591 NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1 SSL_CERT_FILE=/usr/local/share/sandbox-ca.crt CURL_CA_BUNDLE=/usr/local/share/sandbox-ca.crt PIP_CERT=/usr/local/share/sandbox-ca.crt NODE_EXTRA_CA_CERTS=/usr/local/share/sandbox-ca.crt REQUESTS_CA_BUNDLE=/usr/local/share/sandbox-ca.crt
RUN if [ -d /etc/apt ]; then printf "Acquire::https::Proxy \"http://127.0.0.1:33591\";\nAcquire::https::CaInfo \"/usr/local/share/sandbox-ca.crt\";\n" > /etc/apt/apt.conf.d/99sandbox; sed -i "s|http://deb.debian.org|https://deb.debian.org|g" /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null || true; fi
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
ENV HTTPS_PROXY= https_proxy= NO_PROXY= no_proxy= SSL_CERT_FILE= CURL_CA_BUNDLE= PIP_CERT= NODE_EXTRA_CA_CERTS= REQUESTS_CA_BUNDLE=
