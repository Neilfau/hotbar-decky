# Keeps the plugin id and the paired devices in an owner-only JSON file inside a folder only the plugin's user can open,
# and moves a file an earlier version left in the desktop user's settings folder into it.
import contextlib
import errno
import json
import os
import re
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


def _fsync_dir(directory: Path) -> None:
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _read_regular_file(path: Path, *, tighten: bool) -> bytes:
    """Reads a file through one descriptor opened without following a symlink.
    A symlink or a path that is not a regular file is unreadable. With `tighten`, a file with wider
    permissions than 0600 is set back to 0600."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError(errno.ELOOP, "symlink") from None
        raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if tighten and stat.S_IMODE(info.st_mode) & 0o177:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(fd)


def _discard(path: Path) -> None:
    """Removes a file in the desktop user's folder. The copy that matters is already in the state folder,
    so a file that cannot be removed is left for the next start."""
    with contextlib.suppress(OSError):
        os.unlink(path)
        _fsync_dir(path.parent)


class DeviceStore:
    def __init__(self, path: Path, random: Callable[[int], bytes] = os.urandom, legacy_path: Path | None = None):
        """`path` is the device file, in a folder that must belong to this process's user. `legacy_path` is where
        an earlier version kept it, in a folder the desktop user can write: a file there is moved to `path`."""
        self._path = Path(path)
        self._random = random
        self.recovered_from_corruption = False
        self._write_pending = False
        self._secure_directory()
        legacy = self._legacy_elsewhere(legacy_path)
        if os.path.lexists(self._path):
            self._load()
            if legacy is not None:
                _discard(legacy)  # a crash after the copy leaves both files; the new one is the one in use
        elif legacy is not None and self._legacy_present(legacy):
            self._migrate(legacy)
        else:
            self._start_fresh()
        if legacy is not None:
            self._move_legacy_corrupt_files(legacy)

    def _secure_directory(self) -> None:
        """Creates the folder with mode 0700 and refuses one that is a symlink or belongs to another user.
        The folder is opened once without following a symlink, so the checks and the chmod act on the same folder."""
        directory = self._path.parent
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                if info.st_uid != os.geteuid():
                    raise StoreError("the state directory belongs to another user")
                if stat.S_IMODE(info.st_mode) & 0o077:
                    os.fchmod(fd, 0o700)
            finally:
                os.close(fd)
        except OSError as exc:
            raise StoreError("cannot use the state directory") from exc

    def _legacy_elsewhere(self, legacy_path: Path | None) -> Path | None:
        """The legacy path, unless its folder is the state folder (a symlinked settings folder must not make
        the live file look like a legacy one)."""
        if legacy_path is None:
            return None
        legacy = Path(legacy_path)
        with contextlib.suppress(OSError):
            if os.path.samefile(legacy.parent, self._path.parent):
                return None
        return legacy

    @staticmethod
    def _legacy_present(legacy: Path) -> bool:
        try:
            os.lstat(legacy)
        except (FileNotFoundError, NotADirectoryError):
            return False
        except OSError as exc:
            raise StoreError("cannot read the legacy device file") from exc
        return True

    def _migrate(self, legacy: Path) -> None:
        """Copies the legacy file into the state folder, then removes it. The legacy file is never renamed: a
        renamed file would still belong to the desktop user, who could keep it open or linked."""
        try:
            raw = _read_regular_file(legacy, tighten=False)
        except OSError as exc:
            raise StoreError("cannot read the legacy device file") from exc
        try:
            self.plugin_id, self._port, self._devices = _parse(raw)
        except ValueError:
            self._copy_aside(raw)
            self.recovered_from_corruption = True
            _discard(legacy)
            self._start_fresh()
            return
        self._write(self.plugin_id, self._port, self._devices)
        _discard(legacy)

    def _move_legacy_corrupt_files(self, legacy: Path) -> None:
        """Copies the `.corrupt` files an earlier version set aside in the desktop user's folder into the state
        folder and removes them. One that cannot be read or copied stays where it is."""
        pattern = re.compile(re.escape(legacy.name) + r"\.corrupt(\.\d+)?")
        try:
            names = sorted(name for name in os.listdir(legacy.parent) if pattern.fullmatch(name))
        except OSError:
            return
        for name in names:
            entry = legacy.parent / name
            try:
                self._copy_aside(_read_regular_file(entry, tighten=False))
            except (OSError, StoreError):
                continue
            _discard(entry)

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
            raw = _read_regular_file(self._path, tighten=True)
        except OSError as exc:
            raise StoreError("cannot read the device file") from exc
        try:
            self.plugin_id, self._port, self._devices = _parse(raw)
        except ValueError:
            self._set_aside()
            self.recovered_from_corruption = True
            self._start_fresh()

    def _free_aside_name(self) -> Path:
        target = self._path.with_name(self._path.name + ".corrupt")
        n = 0
        while os.path.lexists(target):
            n += 1
            target = self._path.with_name(f"{self._path.name}.corrupt.{n}")
        return target

    def _set_aside(self) -> None:
        try:
            self._path.rename(self._free_aside_name())
        except OSError as exc:
            raise StoreError("cannot move the corrupt device file aside") from exc

    def _copy_aside(self, raw: bytes) -> None:
        self._write_file(self._free_aside_name(), raw)

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
        self._write_file(self._path, json.dumps(doc, indent=2, sort_keys=True).encode("ascii"))
        self._write_pending = False

    def _write_file(self, target: Path, payload: bytes) -> None:
        """Writes `payload` to `target` through an owner-only temporary file that is synced before it replaces the target."""
        tmp = target.with_name(f".{target.name}.{self._random(8).hex()}.tmp")
        try:
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, target)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            _fsync_dir(target.parent)
        except OSError as exc:
            raise StoreError("cannot write the device file") from exc
