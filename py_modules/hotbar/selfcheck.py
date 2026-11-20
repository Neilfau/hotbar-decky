# One-time check of what the plugin's own Python and the machine offer, logged as one line per check with no payload data.
import hashlib
import hmac
import logging
import os
import platform
import secrets
import time
from collections.abc import Callable
from pathlib import Path

from hotbar import crypto

PREFIX = "selfcheck"
_SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def uinput_writable(path: str | Path) -> bool:
    """True if the device can be opened for writing. Opening alone creates nothing."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        return False
    return True


def dir_writable(path: str | Path) -> bool:
    return Path(path).is_dir() and os.access(path, os.W_OK)


def _ok(passed: bool) -> str:
    return "ok" if passed else "failed"


def _yes(value: bool) -> str:
    return "true" if value else "false"


def _sha256() -> str:
    return _ok(hashlib.sha256(b"abc").hexdigest() == _SHA256_ABC)


def _hmac() -> str:
    return _ok(hmac.new(b"k", b"m", "sha256").digest() == hmac.digest(b"k", b"m", "sha256"))


def _secrets() -> str:
    return _ok(len(secrets.token_bytes(8)) == 8)


def _fcntl() -> str:
    import fcntl

    return _ok(callable(fcntl.ioctl))


def _ctypes() -> str:
    import ctypes

    return _ok(ctypes.c_int(7).value == 7)


def _aiohttp() -> str:
    import aiohttp

    return _ok(bool(aiohttp.__version__))


def _ms(work: Callable[[], object]) -> str:
    start = time.perf_counter()
    work()
    return f"{(time.perf_counter() - start) * 1000:.0f} ms"


def _x25519() -> str:
    private, peer = os.urandom(32), crypto.x25519_public(os.urandom(32))
    return _ms(lambda: crypto.x25519_shared(private, peer))


def _seal() -> str:
    key, nonce, body = os.urandom(32), os.urandom(12), bytes(512)
    return _ms(lambda: crypto.aead_seal(key, nonce, b"", body))


def run(logger: logging.Logger, *, uinput_path: str | Path, services_dir: Path) -> list[str]:
    """Runs every check, logs one line each and returns the lines. A failing check is reported, never raised."""
    checks: list[tuple[str, Callable[[], str]]] = [
        ("python", platform.python_version),
        ("hashlib_sha256", _sha256),
        ("hmac", _hmac),
        ("secrets", _secrets),
        ("fcntl", _fcntl),
        ("ctypes", _ctypes),
        ("aiohttp", _aiohttp),
        ("x25519_shared", _x25519),
        ("chacha20poly1305_seal_512", _seal),
        ("effective_uid", lambda: str(os.geteuid())),
        ("uinput_writable", lambda: _yes(uinput_writable(uinput_path))),
        ("avahi_services_dir_writable", lambda: _yes(dir_writable(services_dir))),
    ]
    lines = []
    for name, check in checks:
        try:
            value = check()
        except Exception as exc:
            value = f"failed ({type(exc).__name__})"
        line = f"{PREFIX} {name}: {value}"
        lines.append(line)
        try:
            logger.info(line)
        except Exception:
            pass
    return lines
