# Веб-интерфейс сканера: сборка статики (Node) и раздача через nginx без root.
# nginx проксирует /api/* на FastAPI, поэтому интерфейс и API живут на одном
# origin и CORS не нужен. Адрес API задаётся переменной API_UPSTREAM.

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
ENV API_UPSTREAM=http://api:8000
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
