# Keeps the plugin id and the paired devices in an owner-only JSON file.
import contextlib
import errno
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from hotbar import constants as c
from hotbar.messages import parse_hex


class StoreError(Exception):
    pass


@dataclass(frozen=True)
class Device:
    device_id: bytes
    key: bytes = field(repr=False)
    name: str = field(repr=False)
    created_at: int  # unix seconds


def _device_problem(device: Device) -> str | None:
    if len(device.device_id) != c.DEVICE_ID_LEN or len(device.key) != c.DEVICE_KEY_LEN:
        return "device id or key has the wrong length"
    if not isinstance(device.name, str) or type(device.created_at) is not int or device.created_at < 0:
        return "device name or creation time is invalid"
    return None


def _parse(raw: bytes) -> tuple[bytes, int | None, dict[bytes, Device]]:
    """Reads and validates the file; any fault raises ValueError."""
    try:
        doc = json.loads(raw.decode("utf-8"))
        plugin_id = parse_hex(doc["pluginId"], c.PLUGIN_ID_LEN)
        port = doc["port"]
        if plugin_id is None or not (port is None or (type(port) is int and 1 <= port <= 65535)):
            raise ValueError("bad plugin id or port")
        devices: dict[bytes, Device] = {}
        for entry in doc["devices"]:
            device = Device(
                parse_hex(entry["deviceId"], c.DEVICE_ID_LEN) or b"",
                parse_hex(entry["deviceKey"], c.DEVICE_KEY_LEN) or b"",
                entry["name"],
                entry["createdAt"],
            )
            if _device_problem(device) or device.device_id in devices:
                raise ValueError("bad device entry")
            devices[device.device_id] = device
    except (KeyError, TypeError, RecursionError) as exc:
        raise ValueError("malformed device file") from exc
    return plugin_id, port, devices


class DeviceStore:
    def __init__(self, path: Path, random: Callable[[int], bytes] = os.urandom):
        self._path = Path(path)
        self._random = random
        self.recovered_from_corruption = False
        self._write_pending = False
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise StoreError("cannot create the settings directory") from exc
        if os.path.lexists(self._path):
            self._load()
        else:
            self._start_fresh()

    @property
    def port(self) -> int | None:
        return self._port

    def set_port(self, port: int) -> None:
        if type(port) is not int or not 1 <= port <= 65535:
            raise StoreError("port out of range")
        self._write(self.plugin_id, port, self._devices)
        self._port = port

    def devices(self) -> list[Device]:
        return list(self._devices.values())

    def get(self, device_id: bytes) -> Device | None:
        return self._devices.get(device_id)

    def add(self, device: Device) -> None:
        problem = _device_problem(device)
        if problem is None and device.device_id in self._devices:
            problem = "device id already exists"
        if problem:
            raise StoreError(problem)
        updated = {**self._devices, device.device_id: device}
        self._write(self.plugin_id, self._port, updated)
        self._devices = updated

    def remove(self, device_id: bytes) -> bool:
        if device_id not in self._devices:
            return False
        self._drop({k: v for k, v in self._devices.items() if k != device_id})
        return True

    def remove_all(self) -> None:
        self._drop({})

    @property
    def write_pending(self) -> bool:
        """True while the file still holds state that memory has dropped, after a failed write."""
        return self._write_pending

    def retry_write(self) -> bool:
        """Writes the in-memory state again if a write is pending. Returns True when nothing is pending afterwards."""
        if self._write_pending:
            with contextlib.suppress(StoreError):
                self._write(self.plugin_id, self._port, self._devices)
        return not self._write_pending

    def _drop(self, remaining: dict[bytes, Device]) -> None:
        # A revoked key leaves memory first, so it stops working even if the file write fails.
        self._devices = remaining
        try:
            self._write(self.plugin_id, self._port, remaining)
        except StoreError:
            self._write_pending = True
            raise

    def _start_fresh(self) -> None:
        self.plugin_id = self._random(c.PLUGIN_ID_LEN)
        self._port = None
        self._devices: dict[bytes, Device] = {}
        self._write(self.plugin_id, None, {})

    def _load(self) -> None:
        try:
            raw = self._read_regular_file()
        except OSError as exc:
            raise StoreError("cannot read the device file") from exc
        try:
            self.plugin_id, self._port, self._devices = _parse(raw)
        except ValueError:
            self._set_aside()
            self.recovered_from_corruption = True
            self._start_fresh()

    def _read_regular_file(self) -> bytes:
        """Reads the device file through one descriptor opened without following a symlink.
        A symlink or a path that is not a regular file is unreadable."""
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self._path, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise OSError(errno.ELOOP, "symlink") from None
            raise
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            if stat.S_IMODE(info.st_mode) & 0o177:
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "rb", closefd=False) as handle:
                return handle.read()
        finally:
            os.close(fd)

    def _set_aside(self) -> None:
        target = self._path.with_name(self._path.name + ".corrupt")
        n = 0
        while target.exists():
            n += 1
            target = self._path.with_name(f"{self._path.name}.corrupt.{n}")
        try:
            self._path.rename(target)
        except OSError as exc:
            raise StoreError("cannot move the corrupt device file aside") from exc

    def _write(self, plugin_id: bytes, port: int | None, devices: dict[bytes, Device]) -> None:
        doc = {
            "pluginId": plugin_id.hex(),
            "port": port,
            "devices": [
                {
                    "deviceId": d.device_id.hex(),
                    "deviceKey": d.key.hex(),
                    "name": d.name,
                    "createdAt": d.created_at,
                }
                for d in devices.values()
            ],
        }
        payload = json.dumps(doc, indent=2, sort_keys=True).encode("ascii")
        tmp = self._path.with_name(f".{self._path.name}.{self._random(8).hex()}.tmp")
        try:
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            dir_fd = os.open(self._path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            raise StoreError("cannot write the device file") from exc
        self._write_pending = False
