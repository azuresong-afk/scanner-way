# 5. Справочник

## 1. Командная строка

CLI выполняется внутри контейнера `app`: `docker compose exec app scanner …`.
Общие параметры: `--actor <имя>` — от чьего имени писать журнал аудита
(например, `cli:ivanov`); `--db-url` — адрес БД (по умолчанию из окружения).
Проекты и allowlist заводятся только в вебе или через API.

### 1.1. Прогон

```bash
scanner --actor cli:ivanov run --engagement 1 --targets 192.0.2.0/28 \
    --modules discovery vuln --rate gentle --confirm-authorized
```

| Параметр | Значение |
|---|---|
| `--engagement ID` | проект |
| `--targets …` | адреса и подсети CIDR из allowlist |
| `--modules …` | модули (раздел 5.3); по умолчанию `discovery vuln` |
| `--engine nuclei\|credentialed\|both` | движок поиска уязвимостей (заменяет `vuln`/`auth_inventory` в `--modules`) |
| `--credential ID` | учётная запись актива, можно несколько |
| `--cred-set ID` | набор проверки для `cred_audit`, можно несколько |
| `--rate gentle\|normal\|aggressive` | профиль нагрузки; по умолчанию `gentle` |
| `--name "…"` | своё название прогона |
| `--no-ping` | сканировать хосты, не отвечающие на ping (`nmap -Pn`) |
| `--confirm-authorized` | **обязательно**: цели входят в объём работ по договору |
| `--allow-credentials` | обязательно при входе на хосты по учётным записям |
| `--allow-cred-audit` | обязательно для модуля `cred_audit` |

Прогон из CLI выполняется синхронно; сторож API его не трогает, пока жив
процесс CLI.

### 1.2. Отчёт

```bash
scanner report --run 12 --format pdf --out /app/report-12.pdf [--brief] [--no-plan] [--no-details] [--compare-to 9]
```

`--format html|pdf|docx|json`; `--brief` — краткая версия; `--no-plan` — без
плана устранения; `--no-details` — без раздела «Детальные результаты для инженеров»; `--compare-to ID` — сравнение с более ранним прогоном.

### 1.3. Учётные записи и наборы проверки

```bash
# SSH по ключу / по паролю (пароль запрашивается или берётся из переменной окружения)
scanner credentials add --engagement 1 --name "ДМЗ" --user audit \
    --key-file /data/audit_key [--passphrase-env VAR] --targets 192.0.2.0/28 [--become sudo|none]
scanner credentials add --engagement 1 --name "стенд" --user audit --ask-password --targets 192.0.2.11
# WinRM (порт по умолчанию 5986)
scanner credentials add --engagement 1 --name "Windows" --protocol winrm --user 'CORP\svc_scan' \
    --password-env WINRM_PASS --targets 192.0.2.20
# сетевое устройство: CLI по SSH, учётка только на просмотр (платформа auto или cisco_ios, junos, routeros, …)
scanner credentials add --engagement 1 --name "Коммутаторы" --protocol netssh --platform auto \
    --user scan --password-env NET_PASS --targets 192.0.2.0/27
# SNMP v3 (ключ аутентификации — --password-env, шифрования — --priv-env); v2c: --snmp-version 2c, community — в пароле
scanner credentials add --engagement 1 --name "SNMP" --protocol snmp --snmp-version 3 --user scan \
    --snmp-auth sha --password-env SNMP_AUTH --snmp-priv aes --priv-env SNMP_PRIV --targets 192.0.2.0/27
# СУБД: postgresql | mysql | mssql | oracle (порт по умолчанию 5432 / 3306 / 1433 / 1521)
scanner credentials add --engagement 1 --name "PostgreSQL" --protocol postgresql --user scan_ro \
    --password-env DB_PASS --targets 192.0.2.30 [--db-name postgres]
scanner credentials add --engagement 1 --name "Oracle ERP" --protocol oracle --user scan_ro \
    --password-env DB_PASS --db-name ERPPDB --targets 192.0.2.31
scanner run --engagement 1 --targets 192.0.2.30 --modules discovery db_audit --credential 3 \
    --confirm-authorized --allow-credentials
scanner credentials list --engagement 1
scanner credentials delete --engagement 1 --id 2

# наборы проверки паролей: файл с строками «логин:пароль»
scanner cred-sets add --engagement 1 --name "Слабые" --service ssh --file /data/creds.txt
scanner cred-sets list --engagement 1
scanner cred-sets delete --engagement 1 --id 1
```

Секреты не передаются в аргументах командной строки.

### 1.4. Справочники и комплект данных

| Команда | Действие |
|---|---|
| `scanner feeds sync-bdu --file /data/vullist.xlsx` | загрузить выгрузку БДУ ФСТЭК |
| `scanner feeds sync-nvd [--since ДАТА --until ДАТА \| --cve CVE-… \| --file фид.json.gz]` | загрузить CVE из NVD: полностью, за период (до 120 дней), одну CVE или из файла |
| `scanner feeds sync-msrc [--since 2024-Jan \| --file /data/msrc]` | загрузить бюллетени Microsoft |
| `scanner feeds sync-advisories [--release debian:bookworm] [--file …]` | загрузить бюллетени дистрибутивов (по умолчанию — `ADVISORY_RELEASES`) |
| `scanner feeds sync nvd epss kev …` | обновить источники так же, как автообновление (`bdu`, `nvd`, `nuclei`, `msrc`, `epss`, `kev`, `advisories`) |
| `scanner feeds auto-enabled <источник>` | код возврата 0, если автообновление источника включено |
| `scanner bundle export --out ФАЙЛ.tar [--source nvd …] [--no-nuclei]` | собрать комплект данных |
| `scanner bundle info ФАЙЛ.tar` | состав и даты комплекта |
| `scanner bundle import [ФАЙЛ.tar] [--force]` | загрузить комплект |

### 1.5. Вход через AD

| Команда | Действие |
|---|---|
| `scanner auth ldap-check` | проверить настройки `SCANNER_API_LDAP_*`: связь с контроллером, служебную учётку, таблицу групп и ролей |
| `scanner auth ldap-check --username ivanov [--password-stdin]` | то же и пробный вход пользователя: DN, группы, роли (пароль спрашивается без эха) |

### 1.6. Узел-сканер

Команды выполняются на узле (`docker-compose.node.yml`), без БД; параметры —
переменные `SCANNER_NODE_*` (раздел 5.8). В контейнере узла точка входа уже
`scanner node`, поэтому в compose пишется только действие:
`docker compose -f docker-compose.node.yml --env-file .env.node run --rm node check`.

| Команда | Действие |
|---|---|
| `scanner node run` | агент сетевого узла: подключиться к центру, забирать и выполнять прогоны (так узел работает постоянно) |
| `scanner node run --once` | забрать не больше одного задания, выполнить и выйти (отладка) |
| `scanner node check` | показать центр, локальный allowlist и инструменты узла, проверить связь и токен; предупредить, если сети узла в центре шире локального allowlist |

**Автономный узел** (`docker-compose.node-offline.yml`, без связи с центром).
Точка входа там — `scanner`, поэтому команда пишется целиком:
`docker compose -f docker-compose.node-offline.yml run --rm node node show`.
Каталог узла — `--home` или `SCANNER_NODE_HOME` (в compose `/var/lib/scanner-node`).
Подробно — [offline-node.md](../offline-node.md).

| Команда | Действие |
|---|---|
| `scanner node init --name <имя> --scope <сеть> … --center-key center.pub [--pub-out node.pub] [--force]` | установить узел: создать ключи узла, записать его allowlist (`--scope`) и ключ центра, напечатать оба отпечатка. Повторно — только с `--force` (новые ключи) |
| `scanner node show` | имя, сети, отпечатки ключей, журнал выполненных заданий |
| `scanner node inspect <файл.scnjob>` | проверить подпись и срок задания, показать цели (и какие из них узел реально проверит), модули, учётки без паролей — не выполняя |
| `scanner node run-job <файл.scnjob> --out <каталог> --confirm-authorized [--allow-empty-reference]` | выполнить задание и записать `result-….scnres`. Без справочников БДУ/NVD не запускается (иначе ложно чистый результат), повторно то же задание не выполняет |
| `scanner offline center-key [--out center.pub]` | (в центре) открытый ключ центра для установки узлов |

## 2. REST API

**Адрес.** Через веб: `http://<сервер>:8080/api/…`; напрямую с сервера:
`http://127.0.0.1:8000/…`. Интерактивное описание (OpenAPI) — на самом сервере:
`http://127.0.0.1:8000/docs`.

**Аутентификация.** Получите токен и передавайте его в заголовке:

```bash
TOKEN=$(curl -s -X POST http://<сервер>:8080/api/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"op1","password":"…"}' | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://<сервер>:8080/api/me
```

Токен действует 60 минут. Коды ответа: 401 — нет или истёк токен, 403 — нет
права, 404 — объект не найден, 409 — недопустимо в текущем состоянии
(например, отчёт по идущему прогону), 422 — ошибка параметров, 429 — превышен
лимит (вход, сетевой поиск, проверка учёток).

**Списки** принимают `limit`, `offset`, `sort`, `order`; общее число по
фильтру — в заголовке `X-Total-Count`.

### 2.1. Методы

`{e}` — id проекта, `{r}` — id прогона.

| Метод и путь | Право | Назначение |
|---|---|---|
| **Служебные** | | |
| `GET /health`, `GET /health/ready` | — | живость и готовность |
| `GET /health/status` | — | статусы компонентов сканера без подробностей (503 — есть сбой) |
| `GET /system/health?refresh=` | вход | состояние сканера по компонентам: статус, сводка, подсказка, подробности |
| `GET /auth/config` | — | включены ли вход через AD (`ldap`) и режим 2FA (`mfa`: `off`/`optional`/`required`) |
| `POST /auth/token` | — | вход: токен доступа или, если нужна 2FA, `mfa_required` + `mfa_token` (5 минут; `mfa_enroll` — 2FA ещё не настроена) |
| `POST /auth/mfa` | `mfa_token` | второй шаг: код из приложения или код восстановления → токен доступа |
| `POST /auth/mfa/enroll`, `POST /auth/mfa/enroll/confirm` | `mfa_token` | настройка обязательной 2FA при входе: QR-код, затем код → токен и коды восстановления |
| `GET /me/mfa`, `POST /me/mfa/setup`, `POST /me/mfa/confirm`, `POST /me/mfa/recovery-codes`, `POST /me/mfa/disable` | вход | своя 2FA: состояние, QR-код, включение, новые коды восстановления, отключение (по коду) |
| `DELETE /users/{id}/mfa` | `manage_users` | сбросить 2FA пользователя |
| `GET /me` | вход | текущий пользователь, роли, права |
| `GET/POST /users`, `PATCH /users/{id}`, `PUT /users/{id}/roles` | `manage_users` | пользователи и роли |
| **Проекты и активы** | | |
| `GET/POST /engagements`, `GET/PATCH/DELETE /engagements/{e}` | чтение `view_engagements`, изменение `manage_engagements` | проекты (с прогонами не удаляются) |
| `GET/POST /engagements/{e}/allowlist`, `POST …/allowlist/bulk`, `DELETE …/allowlist/{id}` | чтение `view_engagements`, изменение `manage_allowlist` | allowlist |
| `GET/POST /engagements/{e}/assets`, `POST …/assets/bulk`, `GET/PATCH/DELETE …/assets/{id}` | чтение `view_engagements`, изменение `manage_engagements` | учёт активов |
| `GET/POST …/asset-groups`, `PATCH/DELETE …/asset-groups/{id}`, `GET …/asset-tags` | то же | группы и теги |
| `GET /engagements/{e}/hosts` (`?os_family=`), `GET …/hosts/{host}/latest` | `view_report` | хосты с ОС и последними данными |
| `GET /engagements/{e}/search?q=` | `view_report` | быстрый поиск |
| **Учётные записи** | | |
| `GET/POST /engagements/{e}/credentials`, `DELETE …/{id}` | `host_credentials` | учётные записи активов (без секретов в ответах) |
| `POST /engagements/{e}/credential-check` | `run_scan` + `host_credentials` | проверка входа, до 16 адресов за запрос |
| `GET/POST /engagements/{e}/cred-sets`, `DELETE …/{id}` | `cred_audit` | наборы проверки паролей |
| **Сетевой поиск** | | |
| `POST/GET /engagements/{e}/port-scans`, `GET /port-scans/{id}`, `POST /port-scans/{id}/stop` | запуск `run_scan`, чтение `view_report` | сетевой поиск |
| `POST /engagements/{e}/reachability` | `run_scan` | быстрая проверка доступности адресов |
| **Прогоны** | | |
| `GET /run-profiles` | `view_report` | профили проверки |
| `POST /engagements/{e}/runs/plan` | `run_scan` | итоговый состав прогона до запуска |
| `POST /engagements/{e}/runs` | `run_scan` (+ `host_credentials` / `cred_audit`) | запуск прогона |
| `GET /engagements/{e}/runs` | `view_report` | список прогонов |
| `GET /engagements/{e}/trend?days=&limit=` | `view_report` | динамика для графика |
| `GET /runs/{r}`, `GET /runs/{r}/coverage`, `GET /runs/{r}/events` | `view_report` | прогон, полнота проверки, лента |
| `POST /runs/{r}/stop`, `POST /runs/{r}/retry` | `run_scan` | остановить, повторить |
| `GET /runs/{r}/services`, `GET /runs/{r}/packages` | `view_report` | сервисы и пакеты прогона |
| **Находки и отчёты** | | |
| `GET /runs/{r}/findings`, `GET /runs/{r}/findings/summary`, `GET /findings/{id}` | `view_report` | находки, счётчики, карточка |
| `GET /runs/{r}/fixes` | `view_report` | план устранения «Что исправить» |
| `PUT/DELETE /findings/{id}/false-positive` | `triage_findings` | отметка ложного срабатывания |
| `POST /runs/{r}/false-positives/by-software`, `…/by-software/unmark` | `triage_findings` | отметка всех уязвимостей ПО |
| `GET /engagements/{e}/false-positives` | `view_report` | перечень отметок проекта |
| `GET /runs/{r}/report` | `view_report` | отчёт (параметры — раздел 2.2) |
| **Расписание** | | |
| `GET/POST /engagements/{e}/schedules` | чтение `view_report`, изменение `run_scan` | расписания проекта |
| `GET/PUT/PATCH/DELETE /schedules/{id}`, `POST /schedules/{id}/run` | то же | изменить, выключить (`{"enabled": false}`), удалить, запустить сейчас |
| **Соответствие** | | |
| `GET /compliance/profiles` | `view_report` | каталог профилей |
| `GET /engagements/{e}/compliance-profiles`, `PUT/DELETE …/{profile}` | чтение `view_engagements`, изменение `manage_engagements` | профили проекта |
| `GET /runs/{r}/compliance`, `POST /runs/{r}/compliance/recompute` | `view_report` / `run_scan` | результат и пересчёт |
| **Справочники** | | |
| `GET /feeds`, `GET /feeds/readiness` | `view_engagements` | состояние и готовность |
| `PUT /feeds/{source}`, `POST /feeds/{source}/run` | `manage_engagements` | расписание источника, обновить сейчас |
| `POST /feeds/bdu/upload`, `POST /feeds/advisories/releases` | `manage_engagements` | загрузка файла БДУ, бюллетени выпусков |
| **Уведомления** | | |
| `GET /integrations/types`, `GET /integrations/channels`, `GET /integrations/log` | `view_engagements` | типы, каналы, журнал доставки |
| `POST/PATCH/DELETE /integrations/channels[/{id}]`, `POST …/{id}/test`, `POST /integrations/log/{id}/retry` | `manage_engagements` | управление каналами |
| **Узлы-сканеры** | | |
| `GET /nodes`, `GET /nodes/{id}` | `view_engagements` или `run_scan` | узлы: статус, сети, локальный allowlist, инструменты, прогоны в работе и в очереди |
| `POST /nodes`, `PATCH /nodes/{id}`, `DELETE /nodes/{id}` | `manage_nodes` | завести (ответ содержит токен — один раз), изменить, отключить (`{"enabled": false}`), удалить (409, если есть прогоны в очереди или в работе) |
| `POST /nodes/{id}/token` | `manage_nodes` | перевыпустить токен узла |
| **Автономные узлы** | | |
| `GET /offline/center-key[?format=file]` | `view_engagements` | открытый ключ центра и отпечаток; `format=file` — файл `center.pub` |
| `GET /nodes/{id}/public-key`, `PUT /nodes/{id}/public-key` | `view_engagements` / `manage_nodes` | ключ узла: отпечаток; загрузить `node.pub` (`{"public_key": "scanner-node-key:v1:…"}`; 409 — у узла есть невыполненные задания) |
| `GET /nodes/{id}/offline-jobs` | `view_report` | задания узла и их статусы |
| `GET /runs/{id}/offline` | `view_report` | задание прогона: статус, срок, отпечатки, итог загрузки |
| `POST /runs/{id}/offline/export?valid_days=14`, `GET /runs/{id}/offline/job` | `run_scan` (+ `host_credentials` / `cred_audit`, если в задании учётки) | «Выгрузить задание» (файл `.scnjob`, 1–90 дней), скачать его ещё раз |
| `POST /runs/{id}/offline/cancel` | `run_scan` | отменить задание: прогон «Остановлен», результат по нему не примется |
| `POST /offline/results/preview`, `POST /offline/results` | `run_scan` | тело — файл `.scnres` (`application/octet-stream`, до 256 МБ): открытый заголовок без загрузки; «Загрузить результат» (409 — уже загружен, задание отменено, просрочено или результат не от этого файла задания; 422 — файл повреждён или подпись не сходится, в том числе подпись чужого узла) |
| **Журнал аудита** | | |
| `GET /audit`, `GET /audit/actions`, `GET /audit/export?format=csv\|json` | `view_audit` | журнал, перечень действий, выгрузка |

### 2.2. Основные параметры

**Запуск прогона** `POST /engagements/{e}/runs`:

```json
{
  "targets": ["192.0.2.0/28", "192.0.2.30-192.0.2.40"],
  "profile": "linux_full",
  "modules": ["discovery"],
  "vuln_engine": "both",
  "credential_ids": [3],
  "cred_set_ids": [],
  "rate_profile": "gentle",
  "no_ping": false,
  "name": "Ежемесячная проверка ДМЗ",
  "node_id": null
}
```

В ответе — прогон, число принятых целей и `denied_targets` с причинами.
`node_id` — id узла-сканера (пусто — центральный сервер); то же поле есть у
расписания. У прогона в ответе `node_id`, `node_name`, `node_mode`.

**Узел** `POST /nodes`: `{"name": "Филиал Казань", "mode": "online",
"scope": ["10.1.0.0/24", "10.1.5.10-10.1.5.60"], "description": null,
"allow_credentials": true}`. Сетей — от 1 до 256, в тех же форматах, что allowlist.

### 2.3. Протокол узла-сканера

Путь `/api/node/v1/…` (через веб) — только для узлов: вход по токену узла
`Authorization: Bearer snode_…`, токены пользователей здесь не действуют, а
токен узла не действует в API людей. Узел соединяется только по HTTPS
(исключения — `localhost` и `SCANNER_NODE_ALLOW_HTTP=1`). При mTLS прокси
передаёт результат проверки сертификата заголовками, раздел 5.8.

| Метод и путь | Назначение |
|---|---|
| `POST /node/v1/hello` | регистрация и «на связи»: хост, версия, локальный allowlist, инструменты. Ответ — узел в центре и сети вне локального allowlist |
| `POST /node/v1/jobs/next` | забрать задание: `{"job": null}` или задание (цели уже обрезаны центром, модули, профиль нагрузки, учётки — если разрешены) |
| `POST /node/v1/jobs/{r}/heartbeat` | «жив» и ход прогона; ответ `{"status", "stop"}`, `stop: true` — остановить. 409 — прогон уже не выполняется |
| `POST /node/v1/jobs/{r}/events`, `POST /node/v1/jobs/{r}/audit` | лента прогона (до 500 событий за запрос) и записи аудита узла (до 5000 за запрос) |
| `POST /node/v1/jobs/{r}/result` | результат прогона (JSON, gzip, до `SCANNER_NODE_MAX_RESULT_MB`) |
| `POST /node/v1/jobs/{r}/fail` | узел не смог выполнить прогон: прогон «Ошибка» с причиной |
| `GET /node/v1/nuclei-templates` | архив шаблонов Nuclei центра (`ETag`, 304 без изменений) |
| `POST /node/v1/reference` | чтение справочников центра (БДУ/NVD, бюллетени ОС, MSRC) — только перечисленные методы чтения |

**Находки** `GET /runs/{r}/findings`: `limit` (до 1000), `offset`, `sort`
(`severity`, `priority`, `cvss`, `host`, `title`, `module`, `id`), `order`,
`severity`, `module`, `status` (повторяемые), `host`, `q`, `bdu_only`,
`include_info`, `false_positives=include|exclude|only`.

**Отчёт** `GET /runs/{r}/report`: `format=html|pdf|docx|json`,
`variant=full|brief`, `compare_to=<id>`, `group_id=<id>`, `plan=false`, `details=false`,
`compliance=fstec-117,cis-benchmark` (или `none`).

## 3. Статусы

| Объект | Значения |
|---|---|
| Прогон | `pending` В очереди · `running` Выполняется · `done` Завершён · `partial` Частично · `failed` Ошибка · `stopped` Остановлен · `interrupted` Прерван |
| Находка (сравнение) | `new` Новая · `open` Открыта · `fixed` Устранена · `regression` Регрессия |
| Опасность | `critical` · `high` · `medium` · `low` · `info` |
| Уверенность | `high` Подтверждено · `medium` Вероятно · `low` Не подтверждено |
| Полнота проверки (хост × модуль) | `completed` · `not_applicable` · `skipped` · `unreachable` · `no_credentials` · `timeout` · `error` |
| Проверка учётки | `ok` · `auth_failed` · `timeout` · `unreachable` · `host_key_mismatch` · `no_credential` · `not_in_allowlist` · `partial` |
| Доставка уведомления | `pending` · `retry` · `sent` · `failed` |
| Мера соответствия | `passed` · `failed` · `manual` (проверяется вручную) · `na` (не проверена) |
| Узел-сканер | `online` На связи (запрос не позже 90 с назад) · `offline` Нет связи · `never` Ещё не подключался · `disabled` Отключён · `autonomous` Автономный |
| Задание автономного узла | `exported` Ожидает результат · `imported` Результат загружен · `cancelled` Отменено · `expired` Срок истёк |

## 4. Профили соответствия

| id | Профиль | Уровни |
|---|---|---|
| `fstec-117` | Приказ ФСТЭК России №117 (ГИС) | К1–К3 |
| `fstec-21` | Приказ ФСТЭК России №21 (ИСПДн) | УЗ1–УЗ4 |
| `fstec-239` | Приказ ФСТЭК России №239 (значимые объекты КИИ) | категория 1–3 |
| `cis-controls-v8` | CIS Controls v8 | IG1–IG3 |
| `cis-benchmark` | CIS Benchmark (Linux, по правилам OpenSCAP) | — |

## 5. Модули, профили, приоритет, журнал, параметры

### 5.1. Профили проверки

| id | Название | Модули |
|---|---|---|
| `linux_full` | Полная проверка Linux | `discovery`, `vuln`, `auth_inventory`, `config_audit`, `password_policy` |
| `windows_full` | Полная проверка Windows | `discovery`, `vuln`, `win_inventory` |
| `network_devices` | Сетевое оборудование | `discovery`, `netdev_audit` |
| `dbms` | Проверка СУБД | `discovery`, `db_audit` |
| `network` | Только сетевая проверка | `discovery`, `vuln` |
| `discovery` | Только обнаружение | `discovery` |

### 5.2. Профили нагрузки

| id | Название | Запросов/с | Параллельно | Попыток входа на цель (`cred_audit`) |
|---|---|---|---|---|
| `gentle` | Медленный | 5 | 8 | 3 |
| `normal` | Обычный | 20 | 32 | 5 |
| `aggressive` | Быстрый | 100 | 128 | 8 |

### 5.3. Модули

| id | Название | Дополнительное право | Движок |
|---|---|---|---|
| `discovery` | Обнаружение и инвентаризация | — | nmap |
| `vuln` | Сетевая проверка уязвимостей | — | Nuclei, баннеры |
| `auth_inventory` | Уязвимости по учётной записи (Linux) | `host_credentials` | SSH, бюллетени дистрибутивов |
| `win_inventory` | Windows по WinRM | `host_credentials` | WinRM, MSRC |
| `netdev_audit` | Сетевое оборудование | `host_credentials` | CLI по SSH (только просмотр), SNMP; NVD/БДУ по версии ОС устройства |
| `config_audit` | Аудит конфигураций | `host_credentials` | OpenSCAP, Lynis; добавляет `auth_inventory` и `password_policy` |
| `password_policy` | Парольная политика | — | чтение файлов PAM и `login.defs` |
| `db_audit` | Аудит СУБД | `host_credentials` | psycopg, PyMySQL, pymssql, python-oracledb; NVD/БДУ, MSRC для SQL Server |
| `cred_audit` | Аудит учётных данных | `cred_audit` | SSH, наборы проверки |

Движок `nuclei` = `vuln`; `credentialed` = `auth_inventory` + `win_inventory` +
`netdev_audit`; `both` — все четыре. Модули, для которых в прогоне нет учёток
нужного протокола, из плана убираются.

### 5.4. Идентификаторы находок

| Префикс | Источник |
|---|---|
| `BDU:ГГГГ-NNNNN` | БДУ ФСТЭК |
| `CVE-ГГГГ-N` | CVE/NVD |
| `[OpenSCAP] …`, `LYNIS:…` | правила аудита конфигураций |
| `POLICY:password-…` | парольная политика |
| `DB-PG-…`, `DB-MY-…`, `DB-MS-…`, `DB-ORA-…` | правила аудита СУБД (таблица ниже) |
| `DB-EOL` | ветка СУБД не поддерживается производителем |
| `INFO:db-audit…` | сводка аудита СУБД, отказ входа, СУБД недоступна |
| `CRED:ssh/<логин>` | слабая учётная запись |
| `NETDEV:<правило>` | правило конфигурации сетевого устройства (см. 5.4а) |

### 5.4а. Правила конфигурации сетевого оборудования

Оцениваются по выгрузке конфигурации (только по SSH). В доказательстве пароли,
хэши, community и ключи SNMP заменены на `***`. Правило, к платформе не
относящееся или не определимое по конфигурации, — «не применимо» и находкой
не становится.

| Правило | Что проверяет | Уровень |
|---|---|---|
| `telnet_mgmt` | управление по Telnet | высокий |
| `ssh_v2` | только SSH v2 | средний |
| `http_mgmt` | веб-управление по HTTP | средний |
| `snmp_v12` | SNMP v1/v2c (в т. ч. ответ по учётке v2c) | средний |
| `snmp_rw` | community с правом записи | высокий |
| `snmp_default_community` | community `public`/`private` | критический |
| `password_encryption` | `service password-encryption` и аналоги | средний |
| `enable_secret` | пароль привилегированного режима хранится необратимо | высокий |
| `local_user_secret` | пароли локальных учёток хранятся необратимо | высокий |
| `aaa` | модель AAA | средний |
| `session_timeout` | тайм-аут сеанса управления ≤ 10 мин | низкий |
| `mgmt_acl` | ACL на доступ к управлению | средний |
| `login_banner` | баннер при входе | низкий |
| `remote_logging` | syslog на внешний сервер | средний |
| `ntp` | синхронизация времени | низкий |
| `insecure_services` | лишние службы (small-servers, finger, PAD, bootp и др.) | низкий |
| `source_route` | IP source routing отключён | низкий |
| `login_block` | блокировка после неудачных входов | низкий |
| `ssh_root_login` | вход root по SSH (Junos) | высокий |
| `password_strength` | проверка стойкости паролей | средний |
| `ssh_crypto` | стойкая криптография SSH | низкий |
| `mac_server` | MAC-Telnet / MAC-Winbox (MikroTik) | средний |

Правила участвуют в профилях соответствия (ФСТЭК, CIS) через факт `netdev`.

#### Правила аудита СУБД

Правила — по мотивам CIS Benchmarks соответствующих СУБД (раздел указан в
рекомендации каждой находки). «Не проверено» — у учётки нет права на нужное
представление; такое правило не считается выполненным.

| СУБД | Правила |
|---|---|
| PostgreSQL, Postgres Pro | `DB-PG-SSL` TLS выключен · `DB-PG-PWENC` пароли не SCRAM · `DB-PG-HBA-TRUST` сетевой вход без пароля · `DB-PG-HBA-WEAK` password/md5 в pg_hba · `DB-PG-SUPERUSER` лишние суперпользователи · `DB-PG-PUBLIC-CREATE` CREATE в схеме public · `DB-PG-LOGCONN`, `DB-PG-LOGDISCONN`, `DB-PG-LOGSTMT` журналирование · `DB-PG-PGAUDIT` нет pgaudit |
| MySQL, MariaDB | `DB-MY-EMPTYPW` пустые пароли · `DB-MY-ANON` анонимные учётки · `DB-MY-REMOTEROOT` root по сети · `DB-MY-LOCALINFILE` · `DB-MY-SECUREFILE` · `DB-MY-TLS` require_secure_transport · `DB-MY-NAMERES` · `DB-MY-STRICT` · `DB-MY-PWLIFE` · `DB-MY-LOGERR` · `DB-MY-TESTDB` |
| MS SQL Server | `DB-MS-XPCMD` xp_cmdshell · `DB-MS-ADHOC` · `DB-MS-CLR` · `DB-MS-OLE` · `DB-MS-XDBCHAIN` · `DB-MS-REMOTEACCESS` · `DB-MS-DAC` · `DB-MS-STARTUPPROCS` · `DB-MS-DBMAIL` · `DB-MS-SA` sa включена · `DB-MS-SANAME` · `DB-MS-POLICY` · `DB-MS-EXPIRATION` · `DB-MS-MIXED` смешанная проверка подлинности |
| Oracle Database | `DB-ORA-REMOTEOS` · `DB-ORA-REMOTEROLES` · `DB-ORA-O7DICT` · `DB-ORA-AUDIT` · `DB-ORA-SQL92` · `DB-ORA-FAILEDLOGIN` · `DB-ORA-PWLIFE` · `DB-ORA-PWVERIFY` · `DB-ORA-DEFPWD` пароли по умолчанию · `DB-ORA-PUBLICEXEC` опасные пакеты у PUBLIC |

Уязвимости версии: PostgreSQL, MySQL, MariaDB, Oracle — NVD по CPE и БДУ ФСТЭК
по названию ПО; Postgres Pro — БДУ по названиям Postgres Pro и NVD по версии
PostgreSQL, на которой основана сборка; MS SQL Server — справочник MSRC:
сборка экземпляра против исправлений той же ветки обслуживания (GDR или CU).
После обновления сканера перезагрузите справочник MSRC (`scanner feeds
sync-msrc`): продукты SQL Server в него раньше не попадали.

### 5.5. Ограничения и лимиты

| Лимит | Значение |
|---|---|
| Адресов в прогоне | 4096 |
| Записей в поле целей | 1024 |
| Учёток на хост в прогоне | до 3 на протокол, от самой узкой области |
| Записей в наборе проверки | 200 |
| Одновременных прогонов | 2 (`SCANNER_API_RUN_WORKERS`) |
| Сетевой поиск | 2 одновременно и 6 запусков в минуту на пользователя, 1024 адреса |
| Проверка учёток | 120 хостов в минуту на пользователя, 16 адресов за запрос |
| Файл БДУ через веб | 128 МБ |
| Выгрузка журнала | 100 000 записей |

### 5.6. Формула приоритета

```
приоритет = min(100, базовый_балл × K_kev × K_epss × K_эксплойт × K_актив)
```

| Множитель | Значение |
|---|---|
| базовый балл | CVSS × 10; без CVSS — по опасности: критический 95, высокий 80, средний 55, низкий 25 |
| `K_kev` | 1,50, если CVE в каталоге CISA KEV |
| `K_epss` | EPSS ≥ 0,50 → 1,30; ≥ 0,10 → 1,15; ≥ 0,01 → 1,05; иначе 1,00 |
| `K_эксплойт` | 1,20, если БДУ отмечает наличие эксплойта |
| `K_актив` | критичность актива: низкая 0,80, средняя 1,00, высокая 1,15, критическая 1,30 |

Ярлык: ≥ 85 — критический, ≥ 65 — высокий, ≥ 40 — средний, иначе низкий.
Ранг — место по убыванию балла; при равенстве — по опасности, хосту, порту,
идентификатору и модулю, поэтому порядок детерминирован. Информационные
находки и ложные срабатывания не ранжируются.

### 5.7. Действия журнала аудита

Полный перечень действий, встречающихся в журнале, — `GET /audit/actions`.

| Группа | Действия |
|---|---|
| Вход и пользователи | `login` (результат `ok`, `failure`, `locked`, `mfa_pending`, `mfa_failure`, `ldap_unavailable`; в деталях `method`: `local`/`ldap`), `user_create`, `user_update`, `user_roles` (от `ldap` — по группам AD), `mfa_enable`, `mfa_disable`, `mfa_reset`, `mfa_recovery_codes`, `access_denied` |
| Проекты, allowlist, активы | `engagement_create`, `engagement_update`, `engagement_delete`, `allowlist_add`, `allowlist_remove`, `asset_create`, `asset_update`, `asset_bulk_update`, `asset_delete`, `asset_import`, `asset_group_create`, `asset_group_rename`, `asset_group_delete` |
| Учётки и наборы | `credential_create`, `credential_delete`, `credential_check`, `cred_set_create`, `cred_set_delete` |
| Прогоны | `scan_request` (в т. ч. отказ без допустимых целей), `scan_queue`, `scan_start`, `scan_stop`, `scan_finish`, `scan_requeue`, `deny` (цель вне allowlist), `module_start`, `module_finish`, `module_skip`, `coverage` |
| Движки и модули | `nmap_exec`, `nuclei_exec`, `banner_match`, `auth_inventory_*`, `win_inventory_*`, `netdev_ssh`, `netdev_snmp`, `netdev_match`, `netdev_skip`, `config_audit_*`, `db_audit_*`, `password_policy_*`, `cred_audit_*` (в т. ч. `cred_audit_attempt`, `cred_audit_lockout`, `cred_audit_limit`), `*_deny` |
| Сетевой поиск | `port_scan`, `reachability_check` |
| Расписание | `schedule_create`, `schedule_update`, `schedule_delete`, `schedule_fire` |
| Находки и отчёты | `false_positive_mark`, `false_positive_unmark`, `false_positive_mark_software`, `export` |
| Соответствие | `compliance_eval`, `compliance_recompute`, `compliance_profile_set`, `compliance_profile_delete` |
| Справочники | `feed_sync`, `feed_fetch`, `feed_schedule_update`, `bdu_upload`, `advisory_fetch`, `advisory_release_load`, `feed_bundle_export`, `feed_bundle_import` |
| Уведомления | `channel_create`, `channel_update`, `channel_delete`, `channel_test`, `notification`, `notification_retry` |
| Узлы-сканеры | `node_create`, `node_update`, `node_token_rotate`, `node_delete` (администратор); `node_register`, `node_hello`, `node_auth` (отказ во входе узла: токен, сертификат), `node_job` (задание выдано), `node_result`, `node_result_filtered` (центр отбросил адреса вне разрешённых сетей). Действия на узле (`module_*`, `*_exec`, `deny` по локальному allowlist) пишутся от имени `node:<название>` |
| Автономные узлы | `node_key_set`, `offline_job_export`, `offline_job_download`, `offline_job_cancel`, `offline_job_expire`, `offline_result_import` (отказ — с исходом `denied`). Из загруженного результата — действия узла по заданию от `node:<название>` с полем `offline_job`: `offline_job_start`, `offline_job_finish`, `module_*`, `deny` |
| Журнал | `audit_view`, `audit_export` |

### 5.8. Параметры окружения

Задаются в `.env`; после изменения — `docker compose up -d`. Полные пояснения
к параметрам установки — [INSTALL.md, раздел 3](../INSTALL.md#3-настройка-env).

**Обязательные и сеть**

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `POSTGRES_PASSWORD` | — | пароль БД |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_HOST`, `POSTGRES_PORT` | из `.env.example` | подключение к БД |
| `SCANNER_API_SECRET` | — | ключ подписи токенов (≥ 32) |
| `SCANNER_CREDENTIALS_KEY` | = `SCANNER_API_SECRET` | ключ шифрования секретов (≥ 16) |
| `SCANNER_OFFLINE_KEY` | = `SCANNER_CREDENTIALS_KEY` | секрет, из которого выводятся ключи центра для автономных узлов (≥ 16; не хранится). Смена — переустановка ключа центра на всех автономных узлах |
| `SCANNER_API_BOOTSTRAP_ADMIN`, `SCANNER_API_BOOTSTRAP_PASSWORD` | — | первый администратор |
| `SCANNER_WEB_PORT`, `SCANNER_API_PORT`, `SCANNER_DB_PORT` | 8080, 8000, 5432 | порты хоста |
| `SCANNER_API_PUBLIC_URL` | пусто | внешний адрес для ссылок в уведомлениях |
| `SCANNER_ENV` | пусто | `production` — не стартовать с шаблонными секретами |
| `SCANNER_DB_WAIT_ATTEMPTS` | 30 | попыток дождаться БД при старте (по 2 с) |

**Вход и API**

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `SCANNER_API_TOKEN_TTL_MINUTES` | 60 | срок токена = время бездействия до выхода (интерфейс продлевает токен, пока пользователь работает) |
| `SCANNER_API_SESSION_MAX_HOURS` | 12 | предельный срок сеанса входа: дольше токен не продлевается, нужен новый вход; `0` — без предела |
| `SCANNER_API_LOGIN_MAX_FAILURES`, `SCANNER_API_LOGIN_LOCKOUT_MINUTES` | 5, 15 | защита от перебора |
| `SCANNER_API_CORS_ORIGINS` | пусто | CORS выключен (веб и API на одном origin) |
| `SCANNER_API_LDAP_URL` | пусто (выкл.) | вход через AD/LDAP: контроллеры `ldaps://…` через запятую |
| `SCANNER_API_LDAP_START_TLS`, `SCANNER_API_LDAP_TLS_VERIFY`, `SCANNER_API_LDAP_CA_FILE` | false, true, пусто | STARTTLS для `ldap://`, проверка сертификата, свой корневой сертификат |
| `SCANNER_API_LDAP_BIND_DN`, `SCANNER_API_LDAP_BIND_PASSWORD` | пусто | служебная учётка для поиска |
| `SCANNER_API_LDAP_USER_BASE`, `SCANNER_API_LDAP_USER_FILTER` | —, по `sAMAccountName`/`userPrincipalName` | где и как искать пользователя |
| `SCANNER_API_LDAP_USERNAME_ATTR`, `SCANNER_API_LDAP_DISPLAY_NAME_ATTR` | `sAMAccountName`, `displayName` | логин и имя в «Сканере» |
| `SCANNER_API_LDAP_GROUP_ROLES` | — | группы → роли: `DN=>роль,роль;DN2=>роль` |
| `SCANNER_API_LDAP_NESTED_GROUPS`, `SCANNER_API_LDAP_TIMEOUT_SECONDS` | false, 5 | вложенные группы AD, таймаут |
| `SCANNER_API_MFA` | `off` | двухфакторный вход: `off`, `optional`, `required` |
| `SCANNER_API_MFA_EXEMPT_USERS`, `SCANNER_API_MFA_ISSUER` | пусто, `Scanner` | учётки без 2FA при `required`; имя в приложении-аутентификаторе |

**Прогоны и планировщики**

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `DEFAULT_RATE_PROFILE` | `gentle` | профиль нагрузки по умолчанию |
| `SCANNER_API_RUN_WORKERS` | 2 | одновременных прогонов |
| `SCANNER_API_RUN_HEARTBEAT_SECONDS`, `SCANNER_API_RUN_STALE_SECONDS` | 30, 180 | сторож прерванных прогонов |
| `SCANNER_API_SCHEDULER_TICK_SECONDS` | 30 | проверка расписаний; 0 — выключить |
| `SCANNER_API_TIMEZONE` | `Europe/Moscow` | пояс расписаний по умолчанию |
| `SCANNER_API_FEEDS_TICK_SECONDS` | 60 | проверка расписаний справочников; 0 — выключить |
| `SCANNER_API_HEALTH_TICK_SECONDS` | 300 | монитор состояния сканера и уведомления о сменах состояния; 0 — выключен |
| `SCANNER_API_HEALTH_DISK_PATHS` | `/data` | каталоги для проверки свободного места |
| `SCANNER_API_NOTIFY_TICK_SECONDS` | 30 | очередь повторов уведомлений; 0 — без повторов |
| `SCANNER_API_PORTSCAN_PER_MINUTE`, `…_MAX_ACTIVE`, `…_MAX_TARGETS`, `…_WORKERS` | 6, 2, 1024, 2 | лимиты сетевого поиска |
| `SCANNER_API_REACHABILITY_PER_MINUTE` | 10 | лимит быстрой проверки доступности |
| `SCANNER_API_CREDENTIAL_CHECK_HOSTS_PER_MINUTE`, `…_WORKERS` | 120, 4 | лимиты проверки учёток |

**Вход на хосты**

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `SCANNER_SSH_KNOWN_HOSTS` | `/data/ssh_known_hosts` | запомненные ключи SSH-хостов |
| `SCANNER_SSH_STRICT_HOST_KEYS` | 0 | 1 — только хосты с заранее известным ключом |
| `SCANNER_SSH_PREFLIGHT`, `SCANNER_SSH_ATTEMPTS`, `SCANNER_SSH_RETRY_DELAY_SEC` | 1, 2, 3 | проверка порта и баннера, повторы |
| `SCANNER_WINRM_TLS` | `pin` | `pin` — запоминать сертификат (TOFU); `ca` — проверка цепочки |
| `SCANNER_WINRM_CA_BUNDLE` | пусто | цепочка для `ca` |
| `SCANNER_WINRM_KNOWN_CERTS` | `/data/winrm_known_certs` | запомненные сертификаты |
| `SCANNER_WINRM_STRICT_CERTS` | 0 | 1 — только хосты с заранее известным сертификатом |
| `SCANNER_WINRM_ALLOW_HTTP` | 0 | 1 — разрешить WinRM по HTTP (5985) |
| `SCANNER_NETDEV_COMMAND_TIMEOUT_SEC` | 60 | предел одной команды CLI сетевого устройства, с |
| `SCANNER_NETDEV_SNMP_TIMEOUT_SEC`, `SCANNER_NETDEV_SNMP_RETRIES` | 3, 1 | таймаут запроса SNMP и число повторов |
| `SCANNER_DBAUDIT_CONNECT_TIMEOUT`, `SCANNER_DBAUDIT_QUERY_TIMEOUT` | 10, 30 | аудит СУБД: таймаут подключения и запроса, с |

**Аудит конфигураций**

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `SCANNER_CONFIG_AUDIT_SCAP_DIR` | `/usr/share/xml/scap/ssg/content` | контент SCAP Security Guide |
| `SCANNER_CONFIG_AUDIT_SCAP_CONTENT` | пусто | свой datastream для всех хостов (например, ФСТЭК/ГОСТ) |
| `SCANNER_CONFIG_AUDIT_SCAP_PROFILE` | пусто | профиль XCCDF; пусто — CIS уровня 1 для серверов или standard |
| `SCANNER_CONFIG_AUDIT_LYNIS_BUNDLE` | пусто | свой архив Lynis |
| `SCANNER_CONFIG_AUDIT_COMMAND_TIMEOUT_SEC` | 1800 | предел времени проверки на хосте |

**Справочники**

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `BDU_FSTEC_FEED_PATH`, `BDU_FSTEC_FEED_URL` | `/data/vullist.xlsx`, пусто | файл или зеркало выгрузки БДУ |
| `SCANNER_BDU_AUTOLOAD` | 1 | загрузить БДУ при первом старте |
| `NVD_API_KEY` | пусто | ключ NVD API (ускоряет загрузку) |
| `EPSS_FEED_URL`/`EPSS_FEED_PATH`, `KEV_FEED_URL`/`KEV_FEED_PATH` | адреса FIRST и CISA | источники EPSS и KEV; `*_PATH` — файл для закрытого контура |
| `SCANNER_MSRC_FEED_PATH`, `SCANNER_MSRC_SINCE` | пусто, `2019-Jan` | файлы CVRF; с какого бюллетеня грузить |
| `ADVISORY_RELEASES` | Debian, Ubuntu, RHEL 8/9, ALT p10 | выпуски ОС для бюллетеней |
| `ADVISORY_DIR` | `/data/advisories` | файлы бюллетеней (главнее адреса) |
| `ADVISORY_URL_<СЕМЕЙСТВО>` | адрес вендора | свой адрес (`DEBIAN`, `UBUNTU`, `RHEL`, `ALT`, `ASTRA`, `REDOS`, `ALPINE`) |
| `ADVISORY_ON_DEMAND` | `auto` | подгрузка бюллетеней в прогоне: `auto`, `1`, `0` |
| `SCANNER_NUCLEI_UPDATE` | 1 | обновлять шаблоны Nuclei при старте |
| `NUCLEI_TEMPLATES_DIR` | `$HOME/nuclei-templates` | каталог шаблонов |
| `SCANNER_BUNDLE_AUTOLOAD`, `SCANNER_DATA_BUNDLE_URL` | 1, пусто | автоимпорт комплекта данных и адрес для скачивания |

**Узлы-сканеры: центр** (`.env` центра)

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `SCANNER_NODE_MTLS_VERIFY_HEADER` | пусто (выкл.) | заголовок, в котором HTTPS-прокси передаёт итог проверки сертификата узла (`SUCCESS`); задан — узел без сертификата не входит |
| `SCANNER_NODE_MTLS_FINGERPRINT_HEADER` | пусто | заголовок с отпечатком сертификата; отпечаток закрепляется за узлом при первом входе |
| `SCANNER_NODE_MAX_RESULT_MB` | 256 | наибольший размер результата от узла |

**Узлы-сканеры: узел** (`.env.node`, образец — `.env.node.example`)

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `SCANNER_NODE_SERVER` | — | адрес центра (`https://…`) |
| `SCANNER_NODE_TOKEN` / `SCANNER_NODE_TOKEN_FILE` | — | токен узла или файл с ним |
| `SCANNER_NODE_ALLOWLIST` | — | обязательный локальный allowlist узла |
| `SCANNER_NODE_CA` | системные CA | CA сертификата центра |
| `SCANNER_NODE_CLIENT_CERT`, `SCANNER_NODE_CLIENT_KEY` | пусто | сертификат и ключ для mTLS |
| `SCANNER_NODE_POLL_SECONDS`, `SCANNER_NODE_HEARTBEAT_SECONDS` | 5, 10 | опрос заданий, отметка «жив» |
| `SCANNER_NODE_TEMPLATES_FROM_CENTER` | 1 | шаблоны Nuclei из центра раз в сутки |
| `SCANNER_NODE_SPOOL` | `/var/lib/scanner-node/spool` | очередь неотправленных результатов |
| `SCANNER_NODE_ALLOW_HTTP` | 0 | 1 — центр без TLS (только стенд) |

**Обслуживание**

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `SCANNER_ALLOW_DOWNGRADE` | пусто | 1 — разрешить `alembic downgrade` на рабочей базе (только после резервной копии) |
| `SCANNER_TEST_DATABASE_URL` | пусто | сервер для автотестов PostgreSQL (создают временную базу) |
