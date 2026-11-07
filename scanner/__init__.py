"""Scanner package."""
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("scanner")
except PackageNotFoundError:   # запуск из исходников без установки
    __version__ = "0.1.0"
