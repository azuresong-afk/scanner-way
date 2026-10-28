"""CPE и версии ПО: разбор идентификаторов, нормализация, сравнение версий.

Нужен цепочке «сервис + версия → CPE → CVE»:
  * nmap отдаёт CPE 2.2 (``cpe:/a:apache:http_server:2.4.49``) или только
    название продукта (``Apache httpd``) и версию (``7.4p1 Debian 10+deb9u7``);
  * NVD хранит критерии в формате CPE 2.3 (``cpe:2.3:a:apache:http_server:*:...``)
    с диапазонами версий.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Название продукта из nmap (в нижнем регистре) -> (vendor, product) в терминах CPE.
# Используется, только если nmap не вернул CPE сам.
NMAP_PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "apache tomcat": ("apache", "tomcat"),
    "apache tomcat/coyote jsp engine": ("apache", "tomcat"),
    "nginx": ("f5", "nginx"),
    "openresty": ("openresty", "openresty"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "microsoft iis httpd": ("microsoft", "internet_information_services"),
    "openssh": ("openbsd", "openssh"),
    "dropbear sshd": ("dropbear_ssh_project", "dropbear_ssh"),
    "vsftpd": ("beasts", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "exim smtpd": ("exim", "exim"),
    "postfix smtpd": ("postfix", "postfix"),
    "dovecot imapd": ("dovecot", "dovecot"),
    "dovecot pop3d": ("dovecot", "dovecot"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql db": ("postgresql", "postgresql"),
    "postgresql": ("postgresql", "postgresql"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "redis key-value store": ("redis", "redis"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch rest api": ("elastic", "elasticsearch"),
    "samba smbd": ("samba", "samba"),
    "isc bind": ("isc", "bind"),
    "openssl": ("openssl", "openssl"),
    "squid http proxy": ("squid-cache", "squid"),
    "jetty": ("eclipse", "jetty"),
    "rabbitmq": ("vmware", "rabbitmq"),
    "memcached": ("memcached", "memcached"),
    "zabbix": ("zabbix", "zabbix"),
}

# Синонимы вендоров: NVD со временем переименовывает вендора (nginx -> f5),
# поэтому ищем по продукту с любым из известных вендоров.
VENDOR_SYNONYMS: dict[str, set[str]] = {
    "f5": {"f5", "nginx"},
    "nginx": {"f5", "nginx"},
    "oracle": {"oracle", "mysql"},
    "mysql": {"oracle", "mysql"},
}

_ANY = {"*", ""}
_NA = {"-"}


@dataclass(frozen=True, slots=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"

    @property
    def full_version(self) -> str:
        """Версия с учётом поля update (OpenSSH: 7.4 + p1 -> 7.4p1)."""
        if self.update in _ANY or self.update in _NA:
            return self.version
        return f"{self.version}{self.update}"


def _split_cpe23(body: str) -> list[str]:
    """Разбивает CPE 2.3 по ':' с учётом экранирования '\\:'."""
    parts, cur, esc = [], [], False
    for ch in body:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def parse_cpe(value: str | None) -> Cpe | None:
    """Разбирает CPE 2.2 (``cpe:/a:v:p:ver``) или 2.3 (``cpe:2.3:a:v:p:ver:...``)."""
    if not value:
        return None
    value = value.strip()
    low = value.lower()
    if low.startswith("cpe:2.3:"):
        f = _split_cpe23(value[len("cpe:2.3:"):])
    elif low.startswith("cpe:/"):
        f = value[len("cpe:/"):].split(":")
    else:
        return None
    f += ["*"] * (5 - len(f))
    part, vendor, product, version, update = (x.lower() for x in f[:5])
    if not vendor or not product:
        return None
    return Cpe(part or "a", vendor, product, version or "*", update or "*")


def normalize_name(name: str | None) -> str:
    """Нормализует название ПО для сравнения: нижний регистр, только буквы/цифры."""
    if not name:
        return ""
    return re.sub(r"[^0-9a-zа-яё]+", " ", name.lower()).strip()


def clean_version(version: str | None) -> str | None:
    """Берёт номер версии из баннера: ``7.4p1 Debian 10+deb9u7`` -> ``7.4p1``."""
    if not version:
        return None
    token = version.strip().split()[0] if version.strip() else ""
    token = token.lstrip("vV")
    return token if re.match(r"^\d", token) else None


def service_cpe(service_cpe_value: str | None, product: str | None,
                version: str | None) -> Cpe | None:
    """CPE сервиса: из поля cpe (nmap) или по названию продукта через алиасы."""
    ver = clean_version(version)
    parsed = parse_cpe(service_cpe_value)
    if parsed:
        if parsed.version in _ANY and ver:
            parsed = Cpe(parsed.part, parsed.vendor, parsed.product, ver, parsed.update)
        return parsed
    if not product:
        return None
    key = product.strip().lower()
    vendor, prod = NMAP_PRODUCT_ALIASES.get(key, ("*", re.sub(r"\s+", "_", key)))
    return Cpe("a", vendor, prod, ver or "*")


# ---------- Сравнение версий ----------

_PRERELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "snapshot"}
_PAD = (0, "")


def version_key(version: str) -> tuple:
    """Ключ сортировки версий, устойчивый к смешанным форматам.

    Числа больше любых буквенных частей; буквенная часть после числа
    (``7.4p1``, ``1.1.1k``) — «после» базовой версии, а метки предрелиза
    (``rc``, ``beta``) — «до» неё: 2.4.0rc1 < 2.4.0 < 2.4.0p1 < 2.4.1.
    """
    chunks = re.findall(r"\d+|[a-zA-Z]+", version)
    key: list[tuple[int, object]] = []
    for c in chunks:
        if c.isdigit():
            key.append((1, int(c)))
        elif c.lower() in _PRERELEASE:
            key.append((-1, c.lower()))
        else:
            key.append((0, c.lower()))
    return tuple(key)


def compare_versions(a: str, b: str) -> int:
    ka, kb = list(version_key(a)), list(version_key(b))
    n = max(len(ka), len(kb))
    ka += [_PAD] * (n - len(ka))
    kb += [_PAD] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def version_in_range(version: str, *, exact: str | None = None,
                     start_incl: str | None = None, start_excl: str | None = None,
                     end_incl: str | None = None, end_excl: str | None = None) -> bool:
    """Проверяет версию против точного значения или диапазона (семантика NVD)."""
    if exact is not None and exact not in _ANY:
        if exact in _NA:
            return False
        return compare_versions(version, exact) == 0
    if start_incl and compare_versions(version, start_incl) < 0:
        return False
    if start_excl and compare_versions(version, start_excl) <= 0:
        return False
    if end_incl and compare_versions(version, end_incl) > 0:
        return False
    return not (end_excl and compare_versions(version, end_excl) >= 0)
