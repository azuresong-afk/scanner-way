FROM python:3.12-slim

# Внешние движки-бэкенды (вызываются как процессы; см. лицензии в architecture.md)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        openscap-scanner \
        lynis \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e . || true
COPY . .

CMD ["uvicorn", "scanner.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
