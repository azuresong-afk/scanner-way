"""Платформы сетевого оборудования: определение, команды просмотра, версия.

На устройстве выполняются ТОЛЬКО команды из этого файла (`Platform.setup`,
`version_cmds`, `config_cmd`) — просмотр версии и конфигурации плюс
отключение постраничного вывода в текущей сессии (`terminal length 0` и
аналоги действуют только на сессию и в конфигурацию не пишутся). Ничего из
ввода цели или оператора в команды не подставляется; конфигурационный режим,
`enable`, `write`, `reload` и т. п. не используются.

Версия ОС устройства сопоставляется со справочниками так же, как пакеты
серверов: CPE продукта в NVD (если NVD знает продукт) и названия ПО в БДУ ФСТЭК
(«Cisco IOS», «JunOS», «RouterOS», «Huawei AR3200»…).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Platform:
    key: str
    vendor: str
    os_name: str                         # «Cisco IOS XE»
    family: str                          # набор правил конфигурации (rules.FAMILIES)
    setup: tuple[str, ...] = ()          # команды сессии (отключить пейджинг)
    version_cmds: tuple[str, ...] = ()
    config_cmd: str | None = None
    cpe: str | None = None               # cpe:/o:vendor:product (без версии)
    bdu_names: tuple[str, ...] = ()
    exec_mode: bool = False              # команды через exec (RouterOS)
    vendor_doc: str | None = None        # бюллетени безопасности вендора


PLATFORMS: dict[str, Platform] = {p.key: p for p in (
    Platform("cisco_ios", "Cisco", "Cisco IOS", "ios",
             setup=("terminal length 0", "terminal width 0"),
             version_cmds=("show version",), config_cmd="show running-config",
             cpe="cpe:/o:cisco:ios", bdu_names=("Cisco IOS",),
             vendor_doc="https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    Platform("cisco_xe", "Cisco", "Cisco IOS XE", "ios",
             setup=("terminal length 0", "terminal width 0"),
             version_cmds=("show version",), config_cmd="show running-config",
             cpe="cpe:/o:cisco:ios_xe", bdu_names=("Cisco IOS XE",),
             vendor_doc="https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    Platform("cisco_nxos", "Cisco", "Cisco NX-OS", "nxos",
             setup=("terminal length 0",),
             version_cmds=("show version",), config_cmd="show running-config",
             cpe="cpe:/o:cisco:nx-os", bdu_names=("NX-OS", "Cisco NX-OS"),
             vendor_doc="https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    Platform("cisco_asa", "Cisco", "Cisco ASA", "asa",
             setup=("terminal pager 0",),
             version_cmds=("show version",), config_cmd="show running-config",
             cpe="cpe:/a:cisco:adaptive_security_appliance_software",
             bdu_names=("Adaptive Security Appliance",
                        "Cisco Secure Firewall Adaptive Security Appliance (ASA)"),
             vendor_doc="https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    Platform("junos", "Juniper", "Juniper Junos OS", "junos",
             setup=("set cli screen-length 0", "set cli screen-width 0"),
             version_cmds=("show version",), config_cmd="show configuration | display set",
             cpe="cpe:/o:juniper:junos", bdu_names=("JunOS", "Junos OS"),
             vendor_doc="https://supportportal.juniper.net/s/global-search/"
                        "%40uri?language=en_US#sort=%40sfcec_community_publish_date_formula__c"
                        "%20descending&f:ctype=[Security%20Advisories]"),
    Platform("routeros", "MikroTik", "MikroTik RouterOS", "routeros",
             version_cmds=("/system resource print", "/system identity print"),
             config_cmd="/export terse", cpe="cpe:/o:mikrotik:routeros",
             bdu_names=("RouterOS",), exec_mode=True,
             vendor_doc="https://mikrotik.com/supportsec"),
    Platform("huawei_vrp", "Huawei", "Huawei VRP", "vrp",
             setup=("screen-length 0 temporary",),
             version_cmds=("display version",), config_cmd="display current-configuration",
             vendor_doc="https://www.huawei.com/en/psirt/all-bulletins"),
    Platform("eltex_esr", "Eltex", "Eltex ESR", "esr",
             setup=("terminal datadump",),
             version_cmds=("show version", "show system"), config_cmd="show running-config",
             bdu_names=("ESR",), vendor_doc="https://eltex-co.ru/support/"),
    Platform("eltex_mes", "Eltex", "Eltex MES", "mes",
             setup=("terminal datadump",),
             version_cmds=("show version", "show system"), config_cmd="show running-config",
             vendor_doc="https://eltex-co.ru/support/"),
)}

# Определение по выводу show version / display version / sysDescr.
_DETECT: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cisco_asa", re.compile(r"Adaptive Security Appliance", re.IGNORECASE)),
    ("cisco_nxos", re.compile(r"NX-OS|Nexus Operating System|\bNXOS\b", re.IGNORECASE)),
    ("cisco_xe", re.compile(r"IOS[ -]?XE|\bIOSXE\b|CAT9K_IOSXE", re.IGNORECASE)),
    ("cisco_ios", re.compile(r"Cisco IOS Software|IOS \(tm\)|Cisco Internetwork Operating", re.IGNORECASE)),
    ("junos", re.compile(r"\bJUNOS\b|Juniper Networks", re.IGNORECASE)),
    ("routeros", re.compile(r"RouterOS|MikroTik|^\s*board-name:|\((stable|long-term)\)",
                            re.IGNORECASE | re.MULTILINE)),
    ("huawei_vrp", re.compile(r"Versatile Routing Platform|\bVRP \(R\)|^HUAWEI\b", re.IGNORECASE | re.MULTILINE)),
    ("eltex_esr", re.compile(r"\bESR-?\d|Eltex Service Router", re.IGNORECASE)),
    ("eltex_mes", re.compile(r"\bMES\s?\d{3,4}", re.IGNORECASE)),
)


def detect(text: str) -> str | None:
    """Ключ платформы по тексту версии (show version, sysDescr) или None."""
    for key, rx in _DETECT:
        if rx.search(text or ""):
            return key
    return None


def detect_by_prompt(prompt: str, banner: str = "") -> str | None:
    """Подсказка по приглашению CLI и баннеру SSH до первой команды.

    ``<HUAWEI>`` — Huawei VRP; ``user@host>`` — Juniper; ``[admin@MikroTik] >``
    или баннер ``ROSSSH`` — RouterOS. Cisco-подобные (``sw1#``) различаются
    только по show version."""
    b = banner.lower()
    if "rosssh" in b:
        return "routeros"
    p = prompt.strip()
    if re.match(r"^\[[^\]]*@[^\]]*\]\s*>$", p):
        return "routeros"
    if re.match(r"^<[^<>]+>$", p) or "huawei" in b:
        return "huawei_vrp"
    if re.match(r"^[\w.-]+@[\w.-]+[>#%]$", p):
        return "junos"
    return None


@dataclass(slots=True)
class DeviceInfo:
    platform: str | None = None
    vendor: str | None = None
    os_name: str | None = None
    version: str | None = None           # версия ОС устройства для сопоставления
    model: str | None = None
    hostname: str | None = None
    serial: str | None = None
    source: str = "ssh"                  # ssh | snmp
    raw_descr: str | None = None         # sysDescr (без секретов)
    extra_versions: list[str] = field(default_factory=list)   # кандидаты (Huawei base)

    @property
    def label(self) -> str:
        parts = [self.os_name or self.vendor or "Сетевое устройство"]
        if self.version:
            parts.append(self.version)
        if self.model:
            parts.append(f"({self.model})")
        return " ".join(parts)


def _first(rx: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> str | None:
    m = re.search(rx, text or "", flags)
    return m.group(1).strip() if m else None


def _strip_comma(v: str | None) -> str | None:
    return v.rstrip(",;") if v else v


def _junos_version(raw: str | None) -> str | None:
    """21.4R3-S5.4 -> 21.4R3-S5 (номер сборки после точки NVD не использует)."""
    if not raw:
        return None
    m = re.match(r"^(\d+\.\d+[A-Za-z]+\d+(?:-[A-Za-z]+\d+)?)", raw)
    return m.group(1) if m else raw


def parse_version(platform: str, text: str) -> DeviceInfo:
    """Версия, модель и имя устройства из вывода команд версии (или sysDescr)."""
    p = PLATFORMS.get(platform)
    info = DeviceInfo(platform=platform, vendor=p.vendor if p else None,
                      os_name=p.os_name if p else None)
    t = text or ""
    if platform in ("cisco_ios", "cisco_xe"):
        info.version = _strip_comma(_first(r"\bVersion\s+([0-9][\w.()]*)", t))
        info.model = (_first(r"^Model [Nn]umber\s*:\s*(\S+)", t)
                      or _first(r"^[Cc]isco\s+(\S+)\s+\(.*\)\s+processor", t)
                      or _first(r"^cisco\s+(\S+)\s+\(", t))
        info.hostname = _first(r"^(\S+)\s+uptime is", t)
        info.serial = _first(r"^System [Ss]erial [Nn]umber\s*:\s*(\S+)", t) or _first(
            r"^Processor board ID\s+(\S+)", t)
    elif platform == "cisco_nxos":
        info.version = _strip_comma(_first(r"^\s*NXOS:\s+version\s+(\S+)", t)
                                    or _first(r"^\s*system:\s+version\s+(\S+)", t)
                                    or _first(r"\bVersion\s+([0-9][\w.()]*)", t))
        info.model = (_first(r"^\s*cisco\s+(Nexus\s?\d+\S*)", t)
                      or _first(r"\b(n\d{4}),", t))
        info.hostname = _first(r"^\s*Device name:\s*(\S+)", t)
    elif platform == "cisco_asa":
        info.version = _first(r"Adaptive Security Appliance(?: Software)? Version\s+(\S+)", t)
        info.model = _first(r"^Hardware:\s+([\w-]+)", t)
        info.hostname = _first(r"^(\S+)\s+up\s+\d", t)
        info.serial = _first(r"^Serial Number:\s*(\S+)", t)
    elif platform == "junos":
        raw = (_first(r"^Junos:\s+(\S+)", t)
               or _first(r"^JUNOS (?:Software Release|Base OS boot) \[([^\]]+)\]", t)
               or _first(r"\bJUNOS\s+([0-9][\w.-]+?),", t)
               or _first(r"\bJUNOS\s+([0-9][\w.-]+)", t))
        info.version = _junos_version(raw)
        info.model = _first(r"^Model:\s+(\S+)", t) or _first(r"Juniper Networks, Inc\.\s+(\S+)", t)
        info.hostname = _first(r"^Hostname:\s+(\S+)", t)
    elif platform == "routeros":
        info.version = _first(r"^\s*version:\s*([0-9][\w.]*)", t) or _first(
            r"RouterOS\s+v?([0-9]+\.[0-9][\w.]*)", t)
        info.model = (_first(r"^\s*board-name:\s*(.+?)\s*$", t)
                      or _first(r"^RouterOS\s+(\S+)", t))
        info.hostname = _first(r"^\s*name:\s*(.+?)\s*$", t)
    elif platform == "huawei_vrp":
        m = re.search(r"Version\s+[\d.]+\s+\(([\w-]+)\s+(V\d+R\d+\w*)\)", t, re.IGNORECASE)
        if m:
            info.model, info.version = m.group(1), m.group(2)
        else:
            info.version = _first(r"\b(V\d{3}R\d{3}\w*)", t)
            info.model = _first(r"^HUAWEI\s+([\w-]+)", t)
        if info.version:
            base = re.match(r"^(V\d+R\d+C\d+)", info.version, re.IGNORECASE)
            if base and base.group(1) != info.version:
                info.extra_versions.append(base.group(1))
        info.hostname = None
    elif platform == "eltex_esr":
        info.version = _first(r"^\s*SW version:\s*\n?\s*([0-9][\w.]*)", t) or _first(
            r"\bVersion:?\s*([0-9]+\.[0-9][\w.]*)", t)
        info.model = (_first(r"System type:\s*.*?\b(ESR-\w+)", t)
                      or _first(r"\b(ESR-\w+)", t))
        info.hostname = _first(r"^\s*System name:\s*(\S+)", t)
    elif platform == "eltex_mes":
        info.version = _first(r"^\s*(?:SW )?[Vv]ersion:?\s*([0-9]+\.[0-9][\w.]*)", t)
        info.model = (_first(r"System Description:\s*(MES\s?\d{3,4}\w*)", t)
                      or _first(r"\b(MES\s?\d{3,4}\w*)", t, re.MULTILINE))
        info.hostname = _first(r"^\s*System [Nn]ame:\s*(\S+)", t)
    if info.model:
        info.model = info.model[:64]
    return info


def bdu_names(info: DeviceInfo) -> list[str]:
    """Названия ПО для поиска в БДУ ФСТЭК (у Huawei и Eltex — по модели)."""
    p = PLATFORMS.get(info.platform or "")
    names = list(p.bdu_names) if p else []
    if info.model:
        if info.platform == "huawei_vrp":
            names += [f"Huawei {info.model}", info.model]
        elif info.platform in ("eltex_esr", "eltex_mes"):
            names += [info.model, f"Eltex {info.model}"]
    return list(dict.fromkeys(names))


def cpe_for(info: DeviceInfo) -> str | None:
    """CPE продукта для NVD; у Huawei — прошивка модели (ar3200_firmware)."""
    p = PLATFORMS.get(info.platform or "")
    if p and p.cpe:
        return p.cpe
    if info.platform == "huawei_vrp" and info.model:
        model = re.sub(r"[^a-z0-9]+", "", info.model.lower().split("-")[0])
        return f"cpe:/o:huawei:{model}_firmware" if model else None
    return None
