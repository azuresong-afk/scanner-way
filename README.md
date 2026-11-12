# Scanner — сетевой сканер уязвимостей (авторизованное тестирование)

Инструмент для **авторизованного** security-тестирования по договору
(pentest-by-contract). Сканирует **только** цели из allowlist, с rate limiting и
полным аудитом действий. Оркестрирует проверенные open-source движки (nmap,
Nuclei, OpenSCAP/Lynis) под единым ядром с хранением в
PostgreSQL и отчётами (HTML/PDF/DOCX/JSON).

> Использование против систем без письменного разрешения владельца недопустимо.

## Возможности
1. Обнаружение и инвентаризация — хосты, порты, сервисы, версии, ОС (nmap);
   сетевой поиск без прогона.
2. Поиск уязвимостей с привязкой к БДУ ФСТЭК и CVE/NVD: снаружи (Nuclei,
   баннеры) и по учётной записи — пакеты и ядро Linux по SSH с учётом
   бюллетеней вендора, обновления и ПО Windows по WinRM.
3. Аудит конфигураций — CIS / требования ФСТЭК/ГОСТ (OpenSCAP, Lynis),
   парольная политика.
4. Аудит учётных данных — контролируемая проверка слабых паролей по
   согласованному набору.
5. Приоритизация (CVSS, CISA KEV, EPSS, эксплойт БДУ, критичность актива) и
   план устранения с командами под ОС хоста.
6. Соответствие приказам ФСТЭК №117/21/239 и CIS.
7. Отчёты HTML/PDF/DOCX/JSON, сравнение прогонов, расписания, уведомления
   (почта, Telegram, syslog/CEF, Jira), журнал аудита.

## Документация
Комплект эксплуатационной документации — [`docs/guide/`](docs/guide/README.md):

| Документ | Для кого |
|---|---|
| [Общее описание](docs/guide/01-overview.md) | все |
| [Руководство по установке](docs/guide/02-installation.md) | администратор сервера |
| [Руководство администратора](docs/guide/03-admin-guide.md) | администратор сканера |
| [Руководство оператора](docs/guide/04-operator-guide.md) | оператор, аудитор |
| [Справочник: CLI, API, параметры](docs/guide/05-reference.md) | все, интеграторы |
| [Сведения о выпусках](docs/guide/06-release-notes.md) | все |

Пошаговая установка с учебным стендом: [`docs/INSTALL.md`](docs/INSTALL.md).
Чек-лист приёмочного тестирования: [`docs/TESTING.md`](docs/TESTING.md).
Архитектура и обоснования: [`docs/architecture.md`](docs/architecture.md).
Дорожные карты: [`docs/roadmap.md`](docs/roadmap.md), [`docs/roadmap-v2.md`](docs/roadmap-v2.md).

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
pip install --require-hashes -r requirements-dev.lock && pip install --no-deps -e .
alembic upgrade head          # нужен PostgreSQL; URL в SCANNER_DATABASE_URL
uvicorn scanner.api.main:app --reload
```

### Зависимости и проверки
Версии Python-пакетов зафиксированы в `requirements.lock` (приложение, из него
ставит Dockerfile) и `requirements-dev.lock` (+ инструменты разработки), с
хешами. После правки зависимостей в `pyproject.toml` — `scripts/lock.sh`
(нужен [uv](https://docs.astral.sh/uv/)); обновить пакет —
`scripts/lock.sh --upgrade-package <имя>`, все — `scripts/lock.sh --upgrade`.
CI (workflow `checks`, на каждый PR и раз в неделю) проверяет: `ruff check .`,
совпадение lock-файлов с `pyproject.toml`, `pip-audit` и `npm audit` (блокируют
уязвимости в том, что попадает в образ; по инструментам разработки — отчёт).

## Веб-интерфейс
Каталог [`web/`](web/README.md): React + TypeScript поверх REST API — сводка,
проекты и allowlist, активы, сетевой поиск, запуск и мониторинг прогонов,
план устранения и находки с привязкой к БДУ ФСТЭК и CVE, соответствие
нормативам, отчёты, справочники, уведомления, журнал аудита и управление
пользователями. Светлая и тёмная тема. Работа в интерфейсе —
[Руководство оператора](docs/guide/04-operator-guide.md).

## Структура
```
docs/guide/      эксплуатационная документация
docs/            установка, приёмка, архитектура, дорожные карты
alembic/         миграции схемы БД
scanner/core/    конфиг, allowlist-гейт, rate limit, аудит, оркестратор, модели
scanner/modules/ discovery, vuln, auth_inventory, win_inventory, config_audit,
                 password_policy, cred_audit (общий интерфейс)
scanner/feeds/   справочники: БДУ ФСТЭК, NVD, EPSS, KEV, MSRC, бюллетени ОС, комплект данных
scanner/compliance/  профили соответствия ФСТЭК и CIS
scanner/integrations/  уведомления: почта, Telegram, syslog/CEF, Jira
scanner/reporting/   сравнение прогонов, приоритет, план устранения, отчёты
scanner/api/     FastAPI: REST API, RBAC, планировщики
web/             веб-интерфейс (React + Vite, nginx-образ)
```
