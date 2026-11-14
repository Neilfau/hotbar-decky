# Input devices: the uinput-backed virtual device and an in-memory fake with the same interface.
import fcntl
import os
import struct
from collections.abc import Iterable, Sequence
from typing import Protocol

Event = tuple[int, int, int]  # (type, code, value)

EV_SYN = 0x00
EV_KEY = 0x01
EV_REL = 0x02
SYN_REPORT = 0x00

BUS_VIRTUAL = 0x06
VENDOR_ID = 0x4842
PRODUCT_ID = 0x0001
NAME_MAX = 79  # the kernel's name field is 80 bytes and must stay NUL-terminated


def _ioc(direction: int, nr: int, size: int) -> int:
    # Linux ioctl number layout on x86 and ARM: direction, size, type, number.
    return direction << 30 | size << 16 | ord("U") << 8 | nr


def _io(nr: int) -> int:
    return _ioc(0, nr, 0)


def _iow(nr: int, size: int) -> int:
    return _ioc(1, nr, size)


# struct uinput_setup: struct input_id (bustype, vendor, product, version), name[80], ff_effects_max.
_SETUP = struct.Struct("=HHHH80sI")
# struct input_event on 64-bit Linux: tv_sec, tv_usec, type, code, value. The kernel stamps the time.
_EVENT = struct.Struct("llHHi")

UI_DEV_CREATE = _io(1)
UI_DEV_DESTROY = _io(2)
UI_DEV_SETUP = _iow(3, _SETUP.size)
UI_SET_EVBIT = _iow(100, 4)
UI_SET_KEYBIT = _iow(101, 4)
UI_SET_RELBIT = _iow(102, 4)


class InputError(Exception):
    """A virtual input device could not be opened, set up or written to."""


class InputDevice(Protocol):
    def write(self, events: Sequence[Event]) -> None:
        """Write exactly these events, in order, in one write() call. The caller adds EV_SYN/SYN_REPORT."""

    def close(self) -> None: ...


class FakeDevice:
    """Records events instead of delivering them. Setting `fail` makes write raise OSError."""

    def __init__(self) -> None:
        self.events: list[Event] = []
        self.closed = False
        self.fail = False

    def write(self, events: Sequence[Event]) -> None:
        if self.fail:
            raise OSError("fake device failure")
        self.events.extend(events)

    def close(self) -> None:
        self.closed = True


class UInputDevice:
    """A virtual device created through /dev/uinput that declares only the given keys and relative axes."""

    def __init__(
        self,
        name: str,
        keys: Iterable[int] = (),
        rel_axes: Iterable[int] = (),
        path: str = "/dev/uinput",
    ) -> None:
        self._fd: int | None = None
        keys = sorted(set(keys))
        rel_axes = sorted(set(rel_axes))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as e:
            raise InputError(f"cannot open {path}: {e}") from e
        try:
            if keys:
                fcntl.ioctl(fd, UI_SET_EVBIT, EV_KEY)
                for key in keys:
                    fcntl.ioctl(fd, UI_SET_KEYBIT, key)
            if rel_axes:
                fcntl.ioctl(fd, UI_SET_EVBIT, EV_REL)
                for axis in rel_axes:
                    fcntl.ioctl(fd, UI_SET_RELBIT, axis)
            setup = _SETUP.pack(BUS_VIRTUAL, VENDOR_ID, PRODUCT_ID, 0, name.encode()[:NAME_MAX], 0)
            fcntl.ioctl(fd, UI_DEV_SETUP, setup)
            fcntl.ioctl(fd, UI_DEV_CREATE)
        except OSError as e:
            try:
                os.close(fd)
            except OSError:
                pass
            raise InputError(f"cannot set up the virtual device: {e}") from e
        self._fd = fd

    def write(self, events: Sequence[Event]) -> None:
        if self._fd is None:
            raise InputError("device is closed")
        data = b"".join(_EVENT.pack(0, 0, type_, code, value) for type_, code, value in events)
        try:
            written = os.write(self._fd, data)
        except OSError as e:
            raise InputError(f"write failed: {e}") from e
        if written != len(data):
            raise InputError("short write")

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        # Closing the descriptor destroys the device anyway, so a failed destroy is not worth reporting.
        try:
            fcntl.ioctl(fd, UI_DEV_DESTROY)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
