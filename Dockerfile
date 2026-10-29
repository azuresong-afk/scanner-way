FROM python:3.12-slim

# Внешние движки-бэкенды (вызываются как процессы; см. лицензии в architecture.md):
# nmap — разведка; openscap-scanner/lynis — аудит конфигураций; openssh-client —
# безагентный доступ; iputils-ping — ICMP в проверке доступности хоста;
# libpango/fonts — рендер PDF (WeasyPrint).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        iputils-ping \
        openssh-client \
        openscap-scanner \
        lynis \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        fonts-dejavu-core \
        fonts-inter \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Nuclei — Go-бинарник из релизов ProjectDiscovery (не apt-пакет). Версия и
# архитектура задаются аргументами сборки; по умолчанию linux/amd64.
ARG NUCLEI_VERSION=3.11.1
ARG TARGETARCH=amd64
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    apt-get update && apt-get install -y --no-install-recommends curl unzip; \
    curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    unzip -o -d /usr/local/bin /tmp/nuclei.zip nuclei; \
    rm /tmp/nuclei.zip; \
    apt-get purge -y curl unzip && apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    nuclei -version || true

WORKDIR /app
# Весь исходный код копируется ДО установки пакета: editable-установка
# setuptools находит пакеты по факту их наличия, и если ставить только по
# pyproject.toml (без каталога scanner/), консольная команда `scanner` и
# автозагрузка БДУ в entrypoint падают с ModuleNotFoundError.
COPY . .
RUN pip install --no-cache-dir -e .
RUN chmod +x docker/entrypoint.sh

# Самоподготовка окружения и запуск — см. docker/entrypoint.sh
ENTRYPOINT ["/app/docker/entrypoint.sh"]
