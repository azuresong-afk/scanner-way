# Scanner — сетевой сканер уязвимостей (авторизованное тестирование)

Инструмент для **авторизованного** security-тестирования по договору
(pentest-by-contract). Сканирует **только** цели из allowlist, с rate limiting и
полным аудитом действий. Оркестрирует проверенные open-source движки (nmap,
Nuclei, OpenSCAP/Lynis, опционально OpenVAS) под единым ядром с хранением в
PostgreSQL и отчётами (HTML/PDF/DOCX/JSON).

> Использование против систем без письменного разрешения владельца недопустимо.

## Модули
1. Discovery/inventory — хосты, порты, сервисы, версии, fingerprint ОС (nmap).
2. Vuln detection — сопоставление с CVE/NVD и БДУ ФСТЭК (Nuclei / OpenVAS).
3. Config audit — бенчмарки CIS / требования ФСТЭК/ГОСТ (OpenSCAP / Lynis).
4. Credential audit — контролируемая проверка слабых/дефолтных учёток.
5. Reporting — хранение прогонов, сравнение и тренды (open/fixed/new/regression).

Установка и первый запуск по шагам: [`docs/INSTALL.md`](docs/INSTALL.md).
Чек-лист приёмочного тестирования: [`docs/TESTING.md`](docs/TESTING.md).
Архитектура и обоснования: [`docs/architecture.md`](docs/architecture.md).
Дорожная карта и промты для параллельной разработки: [`docs/roadmap.md`](docs/roadmap.md).

## Статус
Итерация 1 — каркас и интерфейсы. Модули пока заглушки (`NotImplementedError`),
реальное сканирование появляется в следующих итерациях (см. план в architecture.md).

## Быстрый старт (одна команда)
Окружение готовится само: сборка образа со всеми движками (nmap, Nuclei,
OpenSCAP, Lynis), миграции схемы, создание первого администратора, однократная
загрузка выгрузки БДУ ФСТЭК (если файл положен) и запуск API.

```bash
cp .env.example .env
# отредактируйте .env: задайте SCANNER_API_SECRET, пароли БД и администратора
# (по желанию) положите выгрузку БДУ: cp /путь/vullist.xlsx ./data/vullist.xlsx
docker compose up --build        # поднимает web + app + postgres и всё готовит сам
```
- Веб-интерфейс: http://localhost:8080 — вход администратором из
  `SCANNER_API_BOOTSTRAP_ADMIN/PASSWORD`.
- API напрямую: http://localhost:8000 (проверка: `GET /health`). Веб-сервис
  проксирует запросы на API сам (`/api/*`), так что UI и API на одном origin.

Что делает контейнер при старте (`docker/entrypoint.sh`): `alembic upgrade head`
→ одноразовая загрузка БДУ из `BDU_FSTEC_FEED_PATH` → обновление шаблонов Nuclei
(если есть сеть) → запуск API. Роли/права и первый админ создаются самим
приложением, пока в БД нет пользователей.

Загрузка CVE из NVD (по желанию, нужна сеть/ключ):
```bash
docker compose exec app scanner feeds sync-nvd
```

### Запуск без Docker (dev)
```bash
pip install -e ".[dev]"
alembic upgrade head          # нужен PostgreSQL; URL в SCANNER_DATABASE_URL
uvicorn scanner.api.main:app --reload
```

## Веб-интерфейс
Каталог [`web/`](web/README.md): React + TypeScript поверх REST API — дашборд,
договоры и allowlist, запуск и мониторинг прогонов, находки с привязкой к БДУ
ФСТЭК и CVE, разбор по хостам, выгрузка отчётов, журнал аудита и управление
пользователями. Светлая и тёмная тема.

## Структура
```
docs/        архитектура, модель безопасности
db/migrations/   схема БД (DDL)
scanner/core/    конфиг, allowlist-гейт, rate limit, аудит, модели
scanner/modules/ discovery, vuln, config_audit, cred_audit (общий интерфейс)
scanner/feeds/   загрузка справочников NVD и БДУ ФСТЭК
scanner/reporting/  diff прогонов + рендер отчётов
scanner/api/     FastAPI: запуск прогонов, отчёты, RBAC
web/             веб-интерфейс (React + Vite, nginx-образ)
```
