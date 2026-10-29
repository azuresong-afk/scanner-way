"""Пакеты ОС -> ПО в терминах справочников (CPE NVD и названия ПО в БДУ ФСТЭК).

Нужен сопоставлению по данным аутентифицированной инвентаризации: менеджер
пакетов отдаёт имя пакета дистрибутива (``openssh-server``, ``libssl3``,
``apache2``) и версию с эпохой и ревизией (``1:9.2p1-2+deb12u3``), а NVD и БДУ
знают ПО как ``openbsd:openssh`` / «OpenSSH» и версии апстрима (``9.2p1``).

Два способа сопоставления пакета:
  * таблица известных пакетов (``KNOWN_PACKAGES``) — CPE (вендор:продукт) для
    NVD и названия ПО для БДУ. Только так пакет сопоставляется с NVD: поиск по
    одному имени продукта без вендора даёт ложные совпадения (у Jenkins есть
    плагин ``git``, у десятков вендоров — продукт ``server``);
  * прочие пакеты — только с БДУ, по совпадению имени пакета с названием ПО в
    «Версия ПО» (``vim``, ``samba``, ``exim``) и только если такое ПО в БДУ есть.

Ядро Linux не сопоставляется: версия ``uname -r`` у дистрибутивов не совпадает
с версией апстрима (Debian 12 — ``6.1.0-18``, а ядро — 6.1.76), и по БДУ это
десятки тысяч записей «Linux» — сплошь ложные совпадения.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from scanner.feeds.cpe import clean_version, normalize_name


@dataclass(frozen=True, slots=True)
class Software:
    key: str                         # группа пакетов одного ПО (openssh, openssl…)
    label: str                       # название ПО — оно же главное имя в БДУ
    vendor: str | None = None        # CPE vendor (None — пакет сопоставляется только с БДУ)
    product: str | None = None       # CPE product
    bdu_names: tuple[str, ...] = ()  # дополнительные названия ПО в БДУ

    @property
    def cpe(self) -> str | None:
        if not (self.vendor and self.product):
            return None
        return f"cpe:/a:{self.vendor}:{self.product}"


def _sw(key, label, vendor=None, product=None, *bdu):
    return Software(key, label, vendor, product, tuple(bdu))


# Регулярное выражение имени пакета (целиком) -> ПО. Имена пакетов Debian/Ubuntu/
# Astra/ALT (dpkg), RHEL/РЕД ОС/SUSE (rpm) и Alpine (apk).
_KNOWN: list[tuple[str, Software]] = [
    (r"openssh(-server|-client|-clients|-sftp-server)?|ssh",
     _sw("openssh", "OpenSSH", "openbsd", "openssh")),
    (r"openssl|openssl-libs|libssl\d[\w.]*|libcrypto\d[\w.]*",
     _sw("openssl", "OpenSSL", "openssl", "openssl")),
    (r"apache2(-bin|-data|-utils)?|httpd(-core|-tools)?|apache2-mpm-\w+",
     _sw("apache-httpd", "Apache HTTP Server", "apache", "http_server")),
    (r"nginx(-core|-full|-light|-extras|-common)?",
     _sw("nginx", "nginx", "f5", "nginx")),
    (r"bash", _sw("bash", "Bash", "gnu", "bash")),
    (r"sudo(-ldap)?", _sw("sudo", "Sudo", "sudo_project", "sudo")),
    (r"curl|libcurl\d*(-gnutls|-nss)?|libcurl[\w.-]*",
     _sw("curl", "cURL", "haxx", "curl", "curl", "libcurl")),
    (r"bind9(-libs|-utils|-dnsutils)?|bind(-libs|-utils)?",
     _sw("bind", "BIND", "isc", "bind", "BIND 9")),
    (r"samba(-common|-libs|-client)?|libsmbclient\d*",
     _sw("samba", "Samba", "samba", "samba")),
    (r"postgresql-?\d+(\.\d+)?|postgresql(-server)?|postgresql\d+-server",
     _sw("postgresql", "PostgreSQL", "postgresql", "postgresql")),
    (r"mysql-server(-core)?(-\d+\.\d+)?|mysql-community-server|mysql",
     _sw("mysql", "MySQL", "oracle", "mysql", "MySQL Server")),
    (r"mariadb-server(-core)?(-\d+\.\d+)?|mariadb",
     _sw("mariadb", "MariaDB", "mariadb", "mariadb")),
    (r"redis(-server)?", _sw("redis", "Redis", "redis", "redis")),
    (r"exim4(-daemon-\w+|-base)?|exim", _sw("exim", "Exim", "exim", "exim")),
    (r"postfix", _sw("postfix", "Postfix", "postfix", "postfix")),
    (r"dovecot(-core|-imapd|-pop3d)?", _sw("dovecot", "Dovecot", "dovecot", "dovecot")),
    (r"vsftpd", _sw("vsftpd", "vsftpd", "beasts", "vsftpd")),
    (r"proftpd(-basic|-core)?", _sw("proftpd", "ProFTPD", "proftpd", "proftpd")),
    (r"squid\d*", _sw("squid", "Squid", "squid-cache", "squid")),
    (r"tomcat\d*", _sw("tomcat", "Apache Tomcat", "apache", "tomcat", "Tomcat")),
    (r"libc6|libc-bin|glibc(-common)?",
     _sw("glibc", "glibc", "gnu", "glibc", "GNU C Library")),
    (r"systemd", _sw("systemd", "systemd", "systemd_project", "systemd")),
    (r"polkit|policykit-1|libpolkit-gobject-1-0|polkitd",
     _sw("polkit", "Polkit", "polkit_project", "polkit")),
    (r"xz-utils|xz|xz-libs|liblzma\d*", _sw("xz", "XZ Utils", "tukaani", "xz")),
    (r"zlib1g|zlib", _sw("zlib", "zlib", "zlib", "zlib")),
    (r"libxml2", _sw("libxml2", "libxml2", "xmlsoft", "libxml2")),
    (r"libexpat1|expat", _sw("expat", "Expat", "libexpat_project", "libexpat", "libexpat")),
    (r"sqlite3?|libsqlite3-0|sqlite-libs", _sw("sqlite", "SQLite", "sqlite", "sqlite")),
    (r"libgnutls\d+|gnutls", _sw("gnutls", "GnuTLS", "gnu", "gnutls")),
    (r"krb5-libs|libkrb5-3|krb5", _sw("krb5", "MIT Kerberos 5", "mit", "kerberos_5",
                                      "Kerberos 5", "krb5")),
    (r"libnss3|nss", _sw("nss", "Network Security Services", "mozilla", "nss", "NSS")),
    (r"git(-core)?", _sw("git", "Git", "git-scm", "git")),
    (r"vim(-tiny|-common|-runtime|-minimal|-enhanced)?", _sw("vim", "Vim", "vim", "vim")),
    (r"wget2?", _sw("wget", "Wget", "gnu", "wget", "GNU Wget")),
    (r"tar", _sw("tar", "GNU tar", "gnu", "tar", "tar")),
    (r"perl(-base)?", _sw("perl", "Perl", "perl", "perl")),
    (r"python3\.\d+(-minimal)?|libpython3\.\d+(-minimal|-stdlib)?|python3\d*",
     _sw("python", "Python", "python", "python", "CPython")),
    (r"php\d*(\.\d+)?(-cli|-common|-fpm)?|libapache2-mod-php\d*(\.\d+)?",
     _sw("php", "PHP", "php", "php")),
    (r"nodejs", _sw("nodejs", "Node.js", "nodejs", "node.js")),
    (r"openjdk-\d+-(jre|jdk)(-headless)?|java-\d+(\.\d+)*-openjdk(-headless)?",
     _sw("openjdk", "OpenJDK", "oracle", "openjdk")),
    (r"docker-ce|docker\.io|docker", _sw("docker", "Docker", "docker", "docker",
                                         "Docker Engine")),
    (r"containerd(\.io)?", _sw("containerd", "containerd", "linuxfoundation", "containerd")),
    (r"runc", _sw("runc", "runc", "linuxfoundation", "runc")),
    (r"cups(-daemon|-libs)?|libcups2", _sw("cups", "CUPS", "openprinting", "cups")),
    (r"rsync", _sw("rsync", "rsync", "samba", "rsync")),
    (r"ntp|ntpsec", _sw("ntp", "NTP", "ntp", "ntp")),
    (r"chrony", _sw("chrony", "chrony", "tuxfamily", "chrony")),
    (r"rsyslog", _sw("rsyslog", "rsyslog", "rsyslog", "rsyslog")),
    (r"slapd|openldap(-servers|-clients)?|libldap-2\.\d+-\d+|libldap\d*",
     _sw("openldap", "OpenLDAP", "openldap", "openldap")),
    (r"snmpd|net-snmp|libsnmp\d+", _sw("net-snmp", "Net-SNMP", "net-snmp", "net-snmp")),
    (r"dnsmasq(-base)?", _sw("dnsmasq", "Dnsmasq", "thekelleys", "dnsmasq")),
    (r"haproxy", _sw("haproxy", "HAProxy", "haproxy", "haproxy")),
    (r"memcached", _sw("memcached", "Memcached", "memcached", "memcached")),
    (r"zabbix-(agent2?|server-\w+|proxy-\w+)", _sw("zabbix", "Zabbix", "zabbix", "zabbix")),
    (r"firefox", _sw("firefox", "Firefox", "mozilla", "firefox")),
    (r"firefox-esr", _sw("firefox-esr", "Firefox ESR", "mozilla", "firefox_esr")),
    (r"thunderbird", _sw("thunderbird", "Thunderbird", "mozilla", "thunderbird")),
    (r"libreoffice-core|libreoffice", _sw("libreoffice", "LibreOffice", "libreoffice",
                                          "libreoffice")),
    (r"grub2?(-common|-pc|-efi-\w+)?|grub2-tools", _sw("grub", "GRUB2", "gnu", "grub2",
                                                       "GRUB")),
    (r"libpam0g|pam|libpam-modules", _sw("pam", "Linux-PAM", "linux-pam", "linux-pam",
                                         "PAM")),
    (r"dbus|dbus-daemon", _sw("dbus", "D-Bus", "freedesktop", "dbus")),
    (r"avahi-daemon|avahi", _sw("avahi", "Avahi", "avahi", "avahi")),
    (r"less", _sw("less", "less", "gnu", "less")),
    (r"screen", _sw("screen", "GNU Screen", "gnu", "screen", "Screen")),
]
KNOWN_PACKAGES: list[tuple[re.Pattern[str], Software]] = [
    (re.compile(rf"(?:{pat})"), sw) for pat, sw in _KNOWN]

# Не сопоставлять по имени с БДУ: ОС и ядро (см. docstring), мета-пакеты.
_SKIP_GENERIC = {"linux", "kernel", "debian", "ubuntu", "base files", "base passwd",
                 "astra", "redos", "alt", "fedora", "centos", "rhel", "release"}
_KERNEL_RE = re.compile(r"(linux-(image|headers|modules)|kernel(-core|-modules)?)(-.*)?")

_EPOCH_RE = re.compile(r"^\d+:")


def is_kernel(name: str) -> bool:
    return bool(_KERNEL_RE.fullmatch(name))


def lookup(name: str) -> Software | None:
    """ПО по имени пакета из таблицы известных пакетов."""
    for pat, sw in KNOWN_PACKAGES:
        if pat.fullmatch(name):
            return sw
    return None


def generic_software(name: str, bdu_names: set[str]) -> Software | None:
    """ПО для пакета вне таблицы: имя пакета совпадает с названием ПО в БДУ."""
    norm = normalize_name(name)
    if len(norm) < 3 or norm in _SKIP_GENERIC or is_kernel(name):
        return None
    if norm not in bdu_names:
        return None
    return Software(key=f"pkg:{name}", label=name)


def distro_version(version: str) -> str:
    """Версия пакета без эпохи: ``1:9.2p1-2+deb12u3`` -> ``9.2p1-2+deb12u3``."""
    return _EPOCH_RE.sub("", version.strip())


def upstream_version(version: str) -> str | None:
    """Версия апстрима: без эпохи, ревизии дистрибутива и суффиксов сборки.

    ``1:9.2p1-2+deb12u3`` -> ``9.2p1``, ``2.4.62-1~deb12u2`` -> ``2.4.62``,
    ``3.0.7-27.el9`` -> ``3.0.7``, ``1.2.13+dfsg-1`` -> ``1.2.13``.
    ``5.6.1+really5.4.5-1ubuntu0.4`` -> ``5.4.5``: «+really» у Debian/Ubuntu —
    откат на старую версию апстрима (так откатили бэкдор в XZ Utils 5.6.1).
    """
    v = distro_version(version)
    if "-" in v:
        v = v.rsplit("-", 1)[0]
    if "+really" in v:
        v = v.rsplit("+really", 1)[1]
    v = re.split(r"[~+]", v, maxsplit=1)[0]
    return clean_version(v)
