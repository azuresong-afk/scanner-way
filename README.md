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

Архитектура и обоснования: [`docs/architecture.md`](docs/architecture.md).
Дорожная карта и промты для параллельной разработки: [`docs/roadmap.md`](docs/roadmap.md).

## Статус
Итерация 1 — каркас и интерфейсы. Модули пока заглушки (`NotImplementedError`),
реальное сканирование появляется в следующих итерациях (см. план в architecture.md).

## Быстрый старт (dev)
```bash
cp .env.example .env
docker compose up -d        # поднимает app + postgres
# применить схему БД (референс): db/migrations/0001_initial.sql
```

## Веб-интерфейс
Каталог [`web/`](web/README.md): React + TypeScript поверх REST API — дашборд,
договоры и allowlist, запуск и мониторинг прогонов, находки с привязкой к БДУ
ФСТЭК и CVE, разбор по хостам, выгрузка отчётов, журнал аудита и управление
пользователями. Два вида (боковое и верхнее меню), светлая и тёмная тема.

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
