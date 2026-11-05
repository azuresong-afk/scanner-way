"""Правила аудита конфигурации сетевого оборудования.

Каждое правило — проверка текста конфигурации (show running-config, show
configuration | display set, /export terse, display current-configuration) по
мотивам CIS Benchmarks для Cisco IOS / NX-OS / ASA / Juniper и рекомендаций
вендоров; правила сопоставлены с мерами ФСТЭК через каталог соответствия
(`compliance/profiles/checks.yaml`, источник ``netdev``).

Исход правила на устройстве:
  * ``fail`` — нарушение (находка CONFIG ``NETDEV:<id>``);
  * ``pass`` — требование выполнено;
  * ``na``   — правило к платформе не применимо или по конфигурации нельзя
    сделать вывод (значение по умолчанию у платформы различается по
    версиям) — в процент соответствия не входит.

Только строки, относящиеся к правилу, попадают в доказательства, и всегда
после `redact`: пароли, хэши, community SNMP, ключи — маскируются. Полная
конфигурация нигде не сохраняется.

Правила Eltex ESR/MES составлены по документации вендора и подлежат проверке
на стенде (см. docs/TESTING.md, шаг 8з).
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from scanner.core.models import Severity

PASS, FAIL, NA = "pass", "fail", "na"
MAX_EVIDENCE_LINES = 8

# Семейства конфигураций (Platform.family).
FAMILIES = ("ios", "nxos", "asa", "junos", "routeros", "vrp", "esr", "mes")

# ---------- маскирование секретов ----------

_SECRET_WORDS = (r"password|secret|community|key-string|key|pre-shared-key|psk|cipher"
                 r"|irreversible-cipher|encrypted-password|authentication-key|auth-key"
                 r"|priv-key|md5|sha|simple|private-key|passphrase")
# «password 7 0822455D0A16», «secret 5 $1$…», «community public RO»
_AFTER_WORD = re.compile(
    rf"(\b(?:{_SECRET_WORDS})\b)"
    rf"(\s+(?:\d{{1,2}}|irreversible-cipher|cipher|simple|sha256|md5|encrypted)(?=\s))?"
    rf"(\s+)(\"[^\"]*\"|\S+)", re.IGNORECASE)
# RouterOS / ключ=значение: password=…, secret=…, authentication-password=…
_KV = re.compile(r"\b([\w-]*(?:password|secret|passphrase|key|community|psk)[\w-]*)="
                 r"(\"[^\"]*\"|\S+)", re.IGNORECASE)
_HASHES = re.compile(r"\$[0-9a-z]{1,3}\$[^\s\"]+|%\^%#.*?%\^%#|%\$%\$.*?%\$%\$",
                     re.IGNORECASE)
# RouterOS: имя community SNMP — это и есть секрет.
_ROS_COMMUNITY = re.compile(r"^(/snmp community .*?\bname=)(\"[^\"]*\"|\S+)", re.IGNORECASE)


# SNMPv3: «priv aes 128 <ключ>», «priv des <ключ>», «auth sha <ключ>».
_SNMP_V3 = re.compile(r"\b(priv|auth)(\s+(?:aes|des|3des|sha\d*|md5)(?:\s+\d+)?)(\s+)(\S+)",
                      re.IGNORECASE)


def redact(line: str) -> str:
    """Строка конфигурации без секретов (значения после ключевых слов — ****)."""
    if line.startswith("/snmp community"):
        return _ROS_COMMUNITY.sub(lambda m: f"{m.group(1)}****", line)[:300]
    s = _HASHES.sub("****", line)
    s = _SNMP_V3.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}****", s)
    s = _KV.sub(lambda m: f"{m.group(1)}=****", s)
    s = _AFTER_WORD.sub(lambda m: f"{m.group(1)}{m.group(2) or ''}{m.group(3)}****", s)
    return s[:300]


# ---------- разбор конфигурации ----------

@dataclass(slots=True)
class Config:
    """Текст конфигурации, разобранный на строки и блоки (Cisco-подобный отступ)."""
    family: str
    text: str
    lines: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # «!» — разделитель Cisco, «#» — разделитель Huawei и комментарии RouterOS.
        self.lines = [ln.rstrip() for ln in self.text.replace("\r", "").split("\n")
                      if ln.strip() and not ln.lstrip().startswith(("!", "#"))]

    def grep(self, pattern: str, flags: int = re.IGNORECASE) -> list[str]:
        rx = re.compile(pattern, flags)
        return [ln for ln in self.lines if rx.search(ln)]

    def has(self, pattern: str) -> bool:
        return bool(self.grep(pattern))

    def blocks(self, header: str) -> list[list[str]]:
        """Блоки «заголовок + строки с отступом» (line vty 0 4 / user-interface vty)."""
        rx = re.compile(header, re.IGNORECASE)
        out: list[list[str]] = []
        cur: list[str] | None = None
        for ln in self.lines:
            if not ln[:1].isspace():
                cur = [ln] if rx.search(ln) else None
                if cur is not None:
                    out.append(cur)
            elif cur is not None:
                cur.append(ln)
        return out


@dataclass(slots=True)
class RuleResult:
    status: str
    evidence: list[str] = field(default_factory=list)
    note: str | None = None


Evaluator = Callable[[Config], RuleResult]


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: dict[str, str]          # семейство -> что сделать
    checks: dict[str, Evaluator]         # семейство -> проверка
    refs: tuple[str, ...] = ()           # пункты CIS / документы

    @property
    def vuln_id(self) -> str:
        return f"NETDEV:{self.id}"


def _ok(evidence: list[str] | None = None, note: str | None = None) -> RuleResult:
    return RuleResult(PASS, [redact(x) for x in (evidence or [])][:MAX_EVIDENCE_LINES], note)


def _fail(evidence: list[str] | None = None, note: str | None = None) -> RuleResult:
    return RuleResult(FAIL, [redact(x) for x in (evidence or [])][:MAX_EVIDENCE_LINES], note)


def _na(note: str | None = None) -> RuleResult:
    return RuleResult(NA, [], note)


def _present(pattern: str, *, fail_note: str, pass_note: str | None = None) -> Evaluator:
    """Нарушение — строка есть в конфигурации."""
    def ev(c: Config) -> RuleResult:
        hits = c.grep(pattern)
        return _fail(hits, fail_note) if hits else _ok(note=pass_note)
    return ev


def _required(pattern: str, *, fail_note: str) -> Evaluator:
    """Нарушение — строки нет в конфигурации."""
    def ev(c: Config) -> RuleResult:
        hits = c.grep(pattern)
        return _ok(hits) if hits else _fail(note=fail_note)
    return ev


def _explicit(enabled: str, disabled: str, *, fail_note: str, na_note: str) -> Evaluator:
    """Явно включено — нарушение, явно выключено — норма, иначе — не определить."""
    def ev(c: Config) -> RuleResult:
        on = [ln for ln in c.grep(enabled) if not re.match(r"^\s*(no|undo)\s", ln, re.IGNORECASE)]
        if on:
            return _fail(on, fail_note)
        if c.has(disabled):
            return _ok(c.grep(disabled))
        return _na(na_note)
    return ev


def _ros_service_disabled(name: str) -> Callable[[Config], bool]:
    rx = re.compile(rf"^/ip service set .*(\b{name}\b|name={name}\b).*disabled=yes", re.IGNORECASE)
    return lambda c: any(rx.search(ln) for ln in c.lines)


# ---------- проверки по семействам ----------

def _ios_vty(c: Config) -> list[list[str]]:
    return c.blocks(r"^line vty\b")


def _ios_telnet(c: Config) -> RuleResult:
    vty = _ios_vty(c)
    if not vty:
        return _na("в конфигурации нет блоков line vty")
    bad: list[str] = []
    for blk in vty:
        tr = [ln for ln in blk[1:] if re.match(r"^\s*transport input\b", ln, re.IGNORECASE)]
        if not tr:
            bad.append(f"{blk[0].strip()}: transport input не задан (по умолчанию в ряде "
                       "версий IOS разрешён Telnet)")
        elif any(re.search(r"\b(telnet|all)\b", ln, re.IGNORECASE) for ln in tr):
            bad += [f"{blk[0].strip()}: {ln.strip()}" for ln in tr]
    if bad:
        return _fail(bad, "удалённое управление допускает Telnet")
    return _ok([f"{b[0].strip()}: transport input ssh" for b in vty][:3])


def _vrp_telnet(c: Config) -> RuleResult:
    hits = [ln for ln in c.grep(r"^\s*telnet( ipv6)? server enable")
            if not ln.strip().lower().startswith("undo")]
    for blk in c.blocks(r"^user-interface vty\b"):
        hits += [f"{blk[0].strip()}: {ln.strip()}" for ln in blk[1:]
                 if re.match(r"^\s*protocol inbound (telnet|all)\b", ln, re.IGNORECASE)]
    return _fail(hits, "включён Telnet-сервер") if hits else _ok()


def _ros_telnet(c: Config) -> RuleResult:
    if _ros_service_disabled("telnet")(c):
        return _ok(c.grep(r"^/ip service set .*telnet"))
    return _fail(note="служба telnet не отключена (/ip service, по умолчанию включена)")


def _ros_www(c: Config) -> RuleResult:
    if _ros_service_disabled("www")(c):
        return _ok(c.grep(r"^/ip service set .*\bwww\b"))
    return _fail(note="служба www (HTTP) не отключена (/ip service, по умолчанию включена)")


def _ros_insecure(c: Config) -> RuleResult:
    bad = [f"служба {s} не отключена" for s in ("ftp", "api")
           if not _ros_service_disabled(s)(c)]
    return _fail(bad, "включены службы без шифрования") if bad else _ok()


def _ros_snmp_enabled(c: Config) -> bool:
    return c.has(r"^/snmp set .*\benabled=yes")


def _ros_snmp_v12(c: Config) -> RuleResult:
    if not _ros_snmp_enabled(c):
        return _ok(note="SNMP выключен")
    comms = c.grep(r"^/snmp community ")
    plain = [ln for ln in comms if not re.search(r"security=(private|authorized)", ln, re.IGNORECASE)]
    if not comms or plain:
        return _fail(plain or ["/snmp set enabled=yes (community по умолчанию)"],
                     "SNMP v1/v2c разрешён (community без шифрования)")
    return _ok(comms)


def _ros_snmp_rw(c: Config) -> RuleResult:
    if not _ros_snmp_enabled(c):
        return _ok(note="SNMP выключен")
    hits = c.grep(r"^/snmp community .*write-access=yes")
    return _fail(hits, "community SNMP с правом записи") if hits else _ok()


def _ros_snmp_default(c: Config) -> RuleResult:
    if not _ros_snmp_enabled(c):
        return _ok(note="SNMP выключен")
    renamed = c.grep(r"^/snmp community set .*default=yes.*\bname=")
    public = [ln for ln in c.grep(r"^/snmp community .*\bname=(public|private)\b")]
    if public:
        return _fail(public, "используется стандартный community")
    if not renamed and not c.grep(r"^/snmp community set .*default=yes.*disabled=yes"):
        return _fail(note="community по умолчанию (public) не переименован и не отключён")
    return _ok()


def _ros_mgmt_acl(c: Config) -> RuleResult:
    hits = c.grep(r"^/ip service set .*\b(ssh|winbox)\b.*\baddress=\S+")
    if hits:
        return _ok(hits)
    return _fail(note="для ssh/winbox не задан список разрешённых адресов (address=)")


def _ros_mac_server(c: Config) -> RuleResult:
    hits = c.grep(r"^/tool mac-server (mac-winbox )?set .*allowed-interface-list=(?!all\b)\S+")
    hits += c.grep(r"^/tool mac-server (mac-winbox )?set .*disabled=yes")
    if hits:
        return _ok(hits)
    return _fail(note="MAC-Telnet/MAC-Winbox доступны на всех интерфейсах (по умолчанию)")


def _ios_snmp_comms(c: Config) -> list[str]:
    return c.grep(r"^snmp-server community \S+")


def _snmp_default_community(lines: list[str], token_index: int) -> list[str]:
    """Строки со стандартным community (значение в доказательствах маскируется)."""
    out = []
    for ln in lines:
        parts = ln.split()
        if len(parts) > token_index and parts[token_index].strip('"').lower() in (
                "public", "private"):
            out.append(ln)
    return out


def _ios_snmp_default(c: Config) -> RuleResult:
    comms = _ios_snmp_comms(c)
    if not comms:
        return _ok(note="community SNMP не заданы")
    bad = _snmp_default_community(comms, 2)
    return _fail(bad, "стандартный community SNMP (public/private)") if bad else _ok()


def _junos_snmp_default(c: Config) -> RuleResult:
    comms = c.grep(r"^set snmp community \S+")
    if not comms:
        return _ok(note="community SNMP не заданы")
    bad = _snmp_default_community(comms, 3)
    return _fail(bad, "стандартный community SNMP (public/private)") if bad else _ok()


def _ios_exec_timeout(c: Config) -> RuleResult:
    bad, seen = [], []
    for blk in c.blocks(r"^line (vty|con|console|aux)\b"):
        for ln in blk[1:]:
            m = re.match(r"^\s*exec-timeout\s+(\d+)(?:\s+(\d+))?", ln, re.IGNORECASE)
            if not m:
                continue
            minutes, seconds = int(m.group(1)), int(m.group(2) or 0)
            seen.append(f"{blk[0].strip()}: {ln.strip()}")
            if (minutes == 0 and seconds == 0) or minutes * 60 + seconds > 600:
                bad.append(f"{blk[0].strip()}: {ln.strip()}")
    if bad:
        return _fail(bad, "тайм-аут сеанса отключён или больше 10 минут")
    return _ok(seen[:3], None if seen else "exec-timeout по умолчанию (10 минут)")


def _vrp_idle_timeout(c: Config) -> RuleResult:
    bad = []
    for blk in c.blocks(r"^user-interface\b"):
        for ln in blk[1:]:
            m = re.match(r"^\s*idle-timeout\s+(\d+)(?:\s+(\d+))?", ln, re.IGNORECASE)
            if m and ((int(m.group(1)) == 0 and int(m.group(2) or 0) == 0)
                      or int(m.group(1)) * 60 + int(m.group(2) or 0) > 600):
                bad.append(f"{blk[0].strip()}: {ln.strip()}")
    return _fail(bad, "тайм-аут сеанса отключён или больше 10 минут") if bad else _ok()


def _nxos_exec_timeout(c: Config) -> RuleResult:
    vals = []
    for blk in c.blocks(r"^line (vty|console)\b"):
        vals += [(blk[0].strip(), ln.strip(), int(m.group(1))) for ln in blk[1:]
                 if (m := re.match(r"^\s*exec-timeout\s+(\d+)", ln, re.IGNORECASE))]
    bad = [f"{h}: {ln}" for h, ln, v in vals if v == 0 or v > 10]
    if bad:
        return _fail(bad, "тайм-аут сеанса отключён или больше 10 минут")
    if vals:
        return _ok([f"{h}: {ln}" for h, ln, _ in vals])
    return _fail(note="exec-timeout для line vty не задан")


def _asa_ssh_timeout(c: Config) -> RuleResult:
    hits = c.grep(r"^ssh timeout\s+(\d+)")
    for ln in hits:
        if int(ln.split()[2]) > 10:
            return _fail([ln], "тайм-аут SSH-сеанса больше 10 минут")
    return _ok(hits, None if hits else "ssh timeout по умолчанию (5 минут)")


def _ios_vty_acl(c: Config) -> RuleResult:
    vty = _ios_vty(c)
    if not vty:
        return _na("в конфигурации нет блоков line vty")
    bad = [blk[0].strip() for blk in vty
           if not any(re.match(r"^\s*(access-class|ipv6 access-class)\s", ln, re.IGNORECASE)
                      for ln in blk[1:])]
    if bad:
        return _fail([f"{b}: нет access-class" for b in bad],
                     "доступ к управлению не ограничен списком адресов")
    return _ok([f"{b[0].strip()}: access-class задан" for b in vty][:3])


def _vrp_vty_acl(c: Config) -> RuleResult:
    vty = c.blocks(r"^user-interface vty\b")
    if not vty:
        return _na("в конфигурации нет блоков user-interface vty")
    bad = [blk[0].strip() for blk in vty
           if not any(re.match(r"^\s*acl( ipv6)? \S+ inbound", ln, re.IGNORECASE) for ln in blk[1:])]
    if bad:
        return _fail([f"{b}: нет acl … inbound" for b in bad],
                     "доступ к управлению не ограничен списком адресов")
    return _ok()


def _asa_mgmt_acl(c: Config) -> RuleResult:
    ssh = c.grep(r"^ssh \d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+ ")
    any_src = [ln for ln in ssh if re.match(r"^ssh 0\.0\.0\.0 0\.0\.0\.0 ", ln)]
    if any_src:
        return _fail(any_src, "SSH-управление разрешено с любого адреса")
    return _ok(ssh[:3]) if ssh else _na("SSH-управление на ASA не настроено")


def _ios_local_users(c: Config) -> RuleResult:
    bad = [ln for ln in c.grep(r"^username \S+ .*\bpassword\b")
           if not re.search(r"\bsecret\b", ln, re.IGNORECASE)]
    if bad:
        return _fail(bad, "пароль локальной учётной записи хранится обратимо "
                          "(password 0/7 вместо secret)")
    return _ok(c.grep(r"^username \S+ .*\bsecret\b")[:3])


def _ios_enable(c: Config) -> RuleResult:
    pw = c.grep(r"^enable password\b")
    if pw:
        return _fail(pw, "пароль привилегированного режима хранится обратимо")
    sec = c.grep(r"^enable (algorithm-type \S+ )?secret\b")
    return _ok(sec) if sec else _na("пароль enable не задан")


def _nxos_users(c: Config) -> RuleResult:
    bad = c.grep(r"^username \S+ password 0 ")
    return _fail(bad, "пароль хранится открытым текстом") if bad else _ok()


def _vrp_users(c: Config) -> RuleResult:
    bad = c.grep(r"^\s*local-user \S+ password simple\b")
    return _fail(bad, "пароль хранится открытым текстом") if bad else _ok()


def _junos_root_login(c: Config) -> RuleResult:
    hits = c.grep(r"^set system services ssh root-login allow\b")
    return _fail(hits, "вход root по SSH разрешён") if hits else _ok()


def _nxos_password_strength(c: Config) -> RuleResult:
    hits = c.grep(r"^no password strength-check")
    return _fail(hits, "проверка стойкости паролей отключена") if hits else _ok()


# ---------- каталог правил ----------

_CIS_IOS = "https://www.cisecurity.org/benchmark/cisco"
_CIS_JUNIPER = "https://www.cisecurity.org/benchmark/juniper"

RULES: tuple[Rule, ...] = (
    Rule("telnet_mgmt", "Управление устройством по Telnet (пароли открытым текстом)",
         Severity.HIGH,
         "Telnet передаёт логин, пароль и весь сеанс управления без шифрования.",
         {"ios": "В каждом блоке line vty задать «transport input ssh».",
          "nxos": "Выполнить «no feature telnet».",
          "asa": "Удалить строки «telnet <адрес> <маска> <интерфейс>», управлять по SSH.",
          "junos": "Удалить «set system services telnet».",
          "routeros": "/ip service set telnet disabled=yes",
          "vrp": "undo telnet server enable; в user-interface vty — «protocol inbound ssh».",
          "esr": "no ip telnet server",
          "mes": "no ip telnet server"},
         {"ios": _ios_telnet,
          "nxos": _present(r"^feature telnet\b", fail_note="включена функция telnet"),
          "asa": _present(r"^telnet \d", fail_note="разрешён Telnet к устройству"),
          "junos": _present(r"^set system services telnet\b",
                            fail_note="включена служба telnet"),
          "routeros": _ros_telnet, "vrp": _vrp_telnet,
          "esr": _explicit(r"^\s*ip telnet server\b", r"^\s*no ip telnet server\b",
                           fail_note="включён Telnet-сервер",
                           na_note="состояние Telnet-сервера в конфигурации не указано"),
          "mes": _explicit(r"^\s*ip telnet server\b", r"^\s*no ip telnet server\b",
                           fail_note="включён Telnet-сервер",
                           na_note="состояние Telnet-сервера в конфигурации не указано")},
         ("CIS Cisco IOS 1.2.x", "CIS Juniper OS 6.x")),
    Rule("ssh_v2", "Разрешена только версия 2 протокола SSH", Severity.MEDIUM,
         "SSHv1 имеет известные криптографические уязвимости.",
         {"ios": "ip ssh version 2",
          "asa": "ssh version 2",
          "junos": "Удалить «protocol-version v1» из set system services ssh.",
          "vrp": "undo ssh server compatible-ssh1x enable"},
         {"ios": _required(r"^ip ssh version 2\b", fail_note="не задано «ip ssh version 2»"),
          "asa": lambda c: (_fail(c.grep(r"^ssh version 1\b"), "разрешён SSHv1")
                            if c.has(r"^ssh version 1\b") else
                            _ok(c.grep(r"^ssh version 2\b")) if c.has(r"^ssh version 2\b")
                            else _fail(note="не задано «ssh version 2» (по умолчанию "
                                            "допускаются v1 и v2)")),
          "junos": _present(r"^set system services ssh protocol-version v1\b",
                            fail_note="разрешён SSHv1"),
          "vrp": _present(r"^\s*ssh server compatible-ssh1x enable",
                          fail_note="разрешена совместимость с SSHv1")},
         ("CIS Cisco IOS 1.5.x",)),
    Rule("http_mgmt", "Веб-управление по HTTP без шифрования", Severity.MEDIUM,
         "HTTP-интерфейс управления передаёт учётные данные без шифрования.",
         {"ios": "no ip http server (при необходимости — только ip http secure-server).",
          "junos": "Удалить «set system services web-management http», оставить https.",
          "routeros": "/ip service set www disabled=yes (при необходимости — www-ssl).",
          "vrp": "undo http server enable",
          "esr": "no ip http server", "mes": "no ip http server"},
         {"ios": lambda c: (_fail([ln for ln in c.grep(r"^ip http server\b")],
                                  "включён HTTP-сервер") if c.has(r"^ip http server\b")
                            else _ok(c.grep(r"^no ip http server\b"))),
          "junos": _present(r"^set system services web-management http\b",
                            fail_note="включено веб-управление по HTTP"),
          "routeros": _ros_www,
          "vrp": lambda c: (_fail(c.grep(r"^\s*http server enable"), "включён HTTP-сервер")
                            if c.has(r"^\s*http server enable") else _ok()),
          "esr": _explicit(r"^\s*ip http server\b", r"^\s*no ip http server\b",
                           fail_note="включён HTTP-сервер",
                           na_note="состояние HTTP-сервера в конфигурации не указано"),
          "mes": _explicit(r"^\s*ip http server\b", r"^\s*no ip http server\b",
                           fail_note="включён HTTP-сервер",
                           na_note="состояние HTTP-сервера в конфигурации не указано")},
         ("CIS Cisco IOS 2.1.x",)),
    Rule("snmp_v12", "SNMP v1/v2c: community без шифрования и аутентификации",
         Severity.MEDIUM,
         "community SNMP v1/v2c передаётся открытым текстом; используйте SNMPv3 "
         "(authPriv).",
         {"ios": "Удалить «snmp-server community …», настроить snmp-server group/user v3 priv.",
          "nxos": "Удалить «snmp-server community …», использовать пользователей SNMPv3 "
                  "с priv aes-128.",
          "asa": "Удалить «snmp-server community», использовать snmp-server group/user v3.",
          "junos": "Удалить «set snmp community …», настроить set snmp v3 usm.",
          "routeros": "/snmp community set … security=private (SNMPv3) или отключить SNMP.",
          "vrp": "undo snmp-agent community …; snmp-agent sys-info version v3.",
          "esr": "Удалить «snmp-server community», настроить пользователей SNMPv3.",
          "mes": "Удалить «snmp-server community», настроить пользователей SNMPv3."},
         {"ios": _present(r"^snmp-server community \S+", fail_note="задан community SNMP v1/v2c"),
          "nxos": _present(r"^snmp-server community \S+",
                           fail_note="задан community SNMP v1/v2c"),
          "asa": _present(r"^snmp-server (community|host .* community)\b",
                          fail_note="задан community SNMP v1/v2c"),
          "junos": _present(r"^set snmp community \S+", fail_note="задан community SNMP"),
          "routeros": _ros_snmp_v12,
          "vrp": _present(r"^\s*snmp-agent (community\b|sys-info version .*\b(v1|v2c|all)\b)",
                          fail_note="разрешён SNMP v1/v2c"),
          "esr": _present(r"^\s*snmp-server community \S+",
                          fail_note="задан community SNMP v1/v2c"),
          "mes": _present(r"^\s*snmp-server community \S+",
                          fail_note="задан community SNMP v1/v2c")},
         ("CIS Cisco IOS 1.6.x",)),
    Rule("snmp_rw", "Community SNMP с правом записи", Severity.HIGH,
         "community с правом записи позволяет менять конфигурацию устройства по SNMP.",
         {"ios": "Удалить community с RW; для управления использовать SSH.",
          "nxos": "Удалить community с group network-admin (RW).",
          "junos": "Удалить «authorization read-write» у community.",
          "routeros": "/snmp community set … write-access=no",
          "vrp": "undo snmp-agent community write …",
          "esr": "Удалить community с rw.", "mes": "Удалить community с rw."},
         {"ios": _present(r"^snmp-server community \S+( view \S+)? RW\b",
                          fail_note="community с правом записи (RW)"),
          "nxos": _present(r"^snmp-server community \S+ group network-admin\b",
                           fail_note="community с правами network-admin"),
          "junos": _present(r"^set snmp community \S+ authorization read-write",
                            fail_note="community с правом записи"),
          "routeros": _ros_snmp_rw,
          "vrp": _present(r"^\s*snmp-agent community write\b",
                          fail_note="community с правом записи"),
          "esr": _present(r"^\s*snmp-server community \S+ .*\brw\b",
                          fail_note="community с правом записи"),
          "mes": _present(r"^\s*snmp-server community \S+ .*\brw\b",
                          fail_note="community с правом записи")},
         ("CIS Cisco IOS 1.6.x",)),
    Rule("snmp_default_community", "Стандартный community SNMP (public/private)",
         Severity.CRITICAL,
         "Стандартные community известны всем: любой узел сети читает (или меняет) "
         "параметры устройства.",
         {"ios": "Удалить community public/private; перейти на SNMPv3.",
          "nxos": "Удалить community public/private; перейти на SNMPv3.",
          "junos": "Удалить community public/private; перейти на SNMPv3.",
          "routeros": "/snmp community set [find default=yes] name=<случайное> или "
                      "disabled=yes; лучше — SNMPv3.",
          "esr": "Удалить community public/private.", "mes": "Удалить community public/private."},
         {"ios": _ios_snmp_default, "nxos": _ios_snmp_default, "junos": _junos_snmp_default,
          "routeros": _ros_snmp_default, "esr": _ios_snmp_default, "mes": _ios_snmp_default},
         ("CIS Cisco IOS 1.6.2",)),
    Rule("password_encryption", "Шифрование паролей в конфигурации (service "
         "password-encryption)", Severity.MEDIUM,
         "Без него пароли линий и пользователей видны в конфигурации открытым текстом.",
         {"ios": "service password-encryption"},
         {"ios": _required(r"^service password-encryption\b",
                           fail_note="не задано «service password-encryption»")},
         ("CIS Cisco IOS 2.1.x",)),
    Rule("enable_secret", "Пароль привилегированного режима хранится необратимо (enable "
         "secret)", Severity.HIGH,
         "«enable password» хранится обратимо (тип 7 восстанавливается мгновенно).",
         {"ios": "Удалить «enable password», задать «enable algorithm-type scrypt secret …»."},
         {"ios": _ios_enable}, ("CIS Cisco IOS 1.1.x",)),
    Rule("local_user_secret", "Пароли локальных учётных записей хранятся необратимо",
         Severity.HIGH,
         "Пароли «password 0/7» и «password simple» восстанавливаются из конфигурации.",
         {"ios": "username <имя> algorithm-type scrypt secret <пароль> вместо password.",
          "nxos": "Задать пароль без «password 0» (хранится хэшем).",
          "vrp": "local-user <имя> password irreversible-cipher <пароль>."},
         {"ios": _ios_local_users, "nxos": _nxos_users, "vrp": _vrp_users},
         ("CIS Cisco IOS 1.1.x",)),
    Rule("aaa", "Включена модель AAA (централизованная аутентификация и учёт)",
         Severity.MEDIUM,
         "Без AAA нет единой аутентификации администраторов и учёта их команд.",
         {"ios": "aaa new-model; aaa authentication login default group tacacs+ local; "
                 "aaa accounting commands …"},
         {"ios": _required(r"^aaa new-model\b", fail_note="не задано «aaa new-model»")},
         ("CIS Cisco IOS 1.1.1",)),
    Rule("session_timeout", "Тайм-аут неактивного сеанса управления не больше 10 минут",
         Severity.LOW,
         "Брошенный сеанс администратора может быть использован посторонним.",
         {"ios": "В line vty/con: exec-timeout 10 0 (или меньше).",
          "nxos": "line vty: exec-timeout 10",
          "asa": "ssh timeout 10 (или меньше)",
          "junos": "set system login class <класс> idle-timeout 10",
          "vrp": "user-interface vty 0 4: idle-timeout 10 0",
          "mes": "line ssh / line telnet: exec-timeout 10"},
         {"ios": _ios_exec_timeout, "nxos": _nxos_exec_timeout, "asa": _asa_ssh_timeout,
          "junos": _required(r"^set system login class \S+ idle-timeout \d+",
                             fail_note="idle-timeout для классов входа не задан"),
          "vrp": _vrp_idle_timeout,
          "mes": _present(r"^\s*exec-timeout 0\b", fail_note="тайм-аут сеанса отключён")},
         ("CIS Cisco IOS 1.2.x",)),
    Rule("mgmt_acl", "Доступ к управлению ограничен списком разрешённых адресов",
         Severity.MEDIUM,
         "Управляющие службы должны быть доступны только из сети администрирования.",
         {"ios": "В line vty: access-class <ACL> in (ACL — только сеть администрирования).",
          "nxos": "line vty: access-class <ACL> in",
          "asa": "ssh <сеть администрирования> <маска> <интерфейс> вместо 0.0.0.0 0.0.0.0.",
          "junos": "Фильтр на lo0: set interfaces lo0 unit 0 family inet filter input <фильтр>.",
          "routeros": "/ip service set ssh,winbox address=<сеть администрирования>",
          "vrp": "user-interface vty 0 4: acl <номер> inbound"},
         {"ios": _ios_vty_acl,
          "nxos": lambda c: (_ok() if any(re.match(r"^\s*access-class\s", ln, re.IGNORECASE)
                                          for b in c.blocks(r"^line vty\b") for ln in b[1:])
                             else _fail(note="для line vty не задан access-class")),
          "asa": _asa_mgmt_acl,
          "junos": _required(r"^set interfaces lo0 unit \d+ family inet6? filter input \S+",
                             fail_note="на lo0 нет фильтра входящего трафика "
                                       "(защита плоскости управления)"),
          "routeros": _ros_mgmt_acl, "vrp": _vrp_vty_acl},
         ("CIS Cisco IOS 1.2.x", "CIS Juniper OS 6.x")),
    Rule("login_banner", "Предупреждающий баннер при входе", Severity.LOW,
         "Баннер предупреждает о мерах защиты и правилах доступа (ФСТЭК УПД.7).",
         {"ios": "banner login ^C … ^C", "nxos": "banner motd # … #",
          "asa": "banner login …", "junos": "set system login message \"…\"",
          "vrp": "header login information \"…\""},
         {"ios": _required(r"^banner (login|motd|exec)\b", fail_note="баннер не задан"),
          "nxos": _required(r"^banner motd\b", fail_note="баннер не задан"),
          "asa": _required(r"^banner (login|motd|asdm)\b", fail_note="баннер не задан"),
          "junos": _required(r"^set system login message\b", fail_note="баннер не задан"),
          "vrp": _required(r"^\s*header (login|shell)\b", fail_note="баннер не задан")},
         ("CIS Cisco IOS 1.3.x",)),
    Rule("remote_logging", "Журналы событий отправляются на внешний сервер (syslog)",
         Severity.MEDIUM,
         "Без внешнего журнала события безопасности теряются при перезагрузке и "
         "могут быть стёрты нарушителем.",
         {"ios": "logging host <адрес syslog>", "nxos": "logging server <адрес>",
          "asa": "logging host <интерфейс> <адрес>; logging enable",
          "junos": "set system syslog host <адрес> any notice",
          "routeros": "/system logging action add name=remote target=remote "
                      "remote=<адрес>; /system logging add action=remote topics=…",
          "vrp": "info-center loghost <адрес>", "esr": "syslog host <имя> <адрес>",
          "mes": "logging host <адрес>"},
         {"ios": _required(r"^logging (host )?\d+\.\d+\.\d+\.\d+|^logging host \S+",
                           fail_note="внешний syslog не настроен"),
          "nxos": _required(r"^logging server \S+", fail_note="внешний syslog не настроен"),
          "asa": _required(r"^logging host \S+ \S+", fail_note="внешний syslog не настроен"),
          "junos": _required(r"^set system syslog host \S+",
                             fail_note="внешний syslog не настроен"),
          "routeros": _required(r"^/system logging action .*target=remote",
                                fail_note="действие журналирования target=remote не задано"),
          "vrp": _required(r"^\s*info-center loghost \S+",
                           fail_note="внешний syslog не настроен"),
          "esr": _required(r"^\s*syslog host \S+", fail_note="внешний syslog не настроен"),
          "mes": _required(r"^\s*logging host \S+", fail_note="внешний syslog не настроен")},
         ("CIS Cisco IOS 2.2.x",)),
    Rule("ntp", "Синхронизация времени (NTP)", Severity.LOW,
         "Без единого времени журналы разных устройств нельзя сопоставить при "
         "расследовании.",
         {"ios": "ntp server <адрес>", "nxos": "ntp server <адрес>",
          "asa": "ntp server <адрес>", "junos": "set system ntp server <адрес>",
          "routeros": "/system ntp client set enabled=yes servers=<адрес>",
          "vrp": "ntp-service unicast-server <адрес>", "esr": "ntp server <адрес>",
          "mes": "sntp server <адрес>; clock source sntp"},
         {"ios": _required(r"^ntp server \S+", fail_note="NTP-сервер не задан"),
          "nxos": _required(r"^ntp server \S+", fail_note="NTP-сервер не задан"),
          "asa": _required(r"^ntp server \S+", fail_note="NTP-сервер не задан"),
          "junos": _required(r"^set system ntp server \S+", fail_note="NTP-сервер не задан"),
          "routeros": _required(r"^/system ntp client set .*enabled=yes",
                                fail_note="NTP-клиент не включён"),
          "vrp": _required(r"^\s*ntp-service unicast-server \S+",
                           fail_note="NTP-сервер не задан"),
          "esr": _required(r"^\s*ntp server \S+", fail_note="NTP-сервер не задан"),
          "mes": _required(r"^\s*(sntp server|ntp server) \S+",
                           fail_note="сервер времени не задан")},
         ("CIS Cisco IOS 2.2.x",)),
    Rule("insecure_services", "Отключены ненужные и небезопасные службы", Severity.LOW,
         "Службы без шифрования и устаревшие сервисы увеличивают поверхность атаки.",
         {"ios": "no service tcp-small-servers; no service udp-small-servers; "
                 "no ip finger; no service finger",
          "junos": "Удалить «set system services ftp/finger/rlogin».",
          "routeros": "/ip service set ftp,api disabled=yes",
          "vrp": "undo ftp server enable"},
         {"ios": _present(r"^(service (tcp|udp)-small-servers|ip finger|service finger)\b",
                          fail_note="включены small-servers/finger"),
          "junos": _present(r"^set system services (ftp|finger|rlogin|rsh|telnet)\b",
                            fail_note="включены службы без шифрования"),
          "routeros": _ros_insecure,
          "vrp": _present(r"^\s*ftp( ipv6)? server enable", fail_note="включён FTP-сервер")},
         ("CIS Cisco IOS 2.1.x",)),
    Rule("source_route", "Отключена маршрутизация от источника (IP source routing)",
         Severity.LOW,
         "Source routing позволяет отправителю обойти маршрутизацию и фильтрацию.",
         {"ios": "no ip source-route"},
         {"ios": _required(r"^no ip source-route\b",
                           fail_note="не задано «no ip source-route»")},
         ("CIS Cisco IOS 3.1.1",)),
    Rule("login_block", "Блокировка входа после неудачных попыток", Severity.LOW,
         "Ограничение попыток входа замедляет подбор паролей администраторов.",
         {"ios": "login block-for 120 attempts 5 within 60",
          "junos": "set system login retry-options tries-before-disconnect 5 "
                   "lockout-period 15",
          "routeros": "Ограничить доступ к управлению (address=) и включить защиту от "
                      "подбора в межсетевом экране."},
         {"ios": _required(r"^login block-for \d+", fail_note="не задано «login block-for»"),
          "junos": _required(r"^set system login retry-options\b",
                             fail_note="retry-options не заданы")},
         ("CIS Cisco IOS 1.1.x",)),
    Rule("ssh_root_login", "Вход root по SSH запрещён", Severity.HIGH,
         "Прямой вход root по SSH лишает журналирование персональной ответственности.",
         {"junos": "set system services ssh root-login deny"},
         {"junos": _junos_root_login}, ("CIS Juniper OS 6.x",)),
    Rule("password_strength", "Проверка стойкости паролей включена", Severity.MEDIUM,
         "Без проверки администраторы могут задать словарный пароль.",
         {"nxos": "password strength-check"},
         {"nxos": _nxos_password_strength}, ("CIS Cisco NX-OS 1.x",)),
    Rule("ssh_crypto", "Стойкая криптография SSH", Severity.LOW,
         "Слабые алгоритмы SSH ослабляют защиту сеанса управления.",
         {"routeros": "/ip ssh set strong-crypto=yes"},
         {"routeros": _required(r"^/ip ssh set .*strong-crypto=yes",
                                fail_note="strong-crypto не включён")}, ()),
    Rule("mac_server", "MAC-Telnet и MAC-Winbox ограничены", Severity.MEDIUM,
         "MAC-сервер RouterOS даёт доступ к управлению на уровне L2 в обход IP-фильтров.",
         {"routeros": "/tool mac-server set allowed-interface-list=none; "
                      "/tool mac-server mac-winbox set allowed-interface-list=<MGMT>"},
         {"routeros": _ros_mac_server}, ()),
)

RULES_BY_ID = {r.id: r for r in RULES}


@dataclass(slots=True)
class Evaluated:
    rule: Rule
    result: RuleResult


def evaluate(family: str, text: str) -> list[Evaluated]:
    """Все правила семейства по тексту конфигурации."""
    if family not in FAMILIES or not text.strip():
        return []
    cfg = Config(family, text)
    out: list[Evaluated] = []
    for rule in RULES:
        fn = rule.checks.get(family)
        if fn is None:
            continue
        try:
            res = fn(cfg)
        except (ValueError, IndexError, re.error) as e:   # недоверенный вывод
            res = _na(f"не удалось разобрать конфигурацию: {type(e).__name__}")
        out.append(Evaluated(rule, res))
    return out
