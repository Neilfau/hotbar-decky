# Tests for the fake device and the uinput device, with os and fcntl replaced by recorders.
import os
import struct
import types

import pytest

from hotbar.input import device
from hotbar.input.device import FakeDevice, InputError, UInputDevice

FD = 42
EV_KEY, EV_REL = 1, 2


class Recorder:
    """Stands in for the os and fcntl modules inside hotbar.input.device."""

    def __init__(self):
        self.calls = []
        self.fail_open = False
        self.fail_ioctl_on = None
        self.fail_destroy = False
        self.fail_write = False
        self.fail_close = False
        self.short_write = False
        self.os = types.SimpleNamespace(
            O_WRONLY=os.O_WRONLY,
            O_NONBLOCK=os.O_NONBLOCK,
            open=self._open,
            write=self._write,
            close=self._close,
        )
        self.fcntl = types.SimpleNamespace(ioctl=self._ioctl)

    def _open(self, path, flags):
        self.calls.append(("open", path, flags))
        if self.fail_open:
            raise PermissionError(13, "denied")
        return FD

    def _ioctl(self, fd, request, arg=0):
        self.calls.append(("ioctl", fd, request, arg))
        if request == device.UI_DEV_DESTROY and self.fail_destroy:
            raise OSError(5, "io")
        if request == self.fail_ioctl_on:
            raise OSError(22, "invalid")
        return 0

    def _write(self, fd, data):
        self.calls.append(("write", fd, data))
        if self.fail_write:
            raise BlockingIOError(11, "again")
        return len(data) - 24 if self.short_write else len(data)

    def _close(self, fd):
        self.calls.append(("close", fd))
        if self.fail_close:
            raise OSError(9, "bad fd")


@pytest.fixture
def rec(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(device, "os", recorder.os)
    monkeypatch.setattr(device, "fcntl", recorder.fcntl)
    return recorder


def packed(type_, code, value):
    return struct.pack("llHHi", 0, 0, type_, code, value)


def test_ioctl_numbers_match_linux():
    assert device.UI_SET_EVBIT == 0x40045564
    assert device.UI_SET_KEYBIT == 0x40045565
    assert device.UI_SET_RELBIT == 0x40045566
    assert device.UI_DEV_SETUP == 0x405C5503
    assert device.UI_DEV_CREATE == 0x5501
    assert device.UI_DEV_DESTROY == 0x5502


def test_setup_and_event_struct_sizes():
    assert device._SETUP.size == 92
    assert device._EVENT.size == 24


def test_creation_sequence(rec):
    UInputDevice("HotBar Test", keys=[30, 1, 30], rel_axes=[1, 0])
    setup = struct.pack("=HHHH80sI", 0x06, device.VENDOR_ID, device.PRODUCT_ID, 0, b"HotBar Test", 0)
    assert len(setup) == 92
    assert rec.calls == [
        ("open", "/dev/uinput", os.O_WRONLY | os.O_NONBLOCK),
        ("ioctl", FD, 0x40045564, EV_KEY),
        ("ioctl", FD, 0x40045565, 1),
        ("ioctl", FD, 0x40045565, 30),
        ("ioctl", FD, 0x40045564, EV_REL),
        ("ioctl", FD, 0x40045566, 0),
        ("ioctl", FD, 0x40045566, 1),
        ("ioctl", FD, 0x405C5503, setup),
        ("ioctl", FD, 0x5501, 0),
    ]


def test_only_declared_event_types_are_enabled(rec):
    UInputDevice("Keys only", keys=[30])
    assert [c for c in rec.calls if c[:3] == ("ioctl", FD, 0x40045564)] == [("ioctl", FD, 0x40045564, EV_KEY)]
    rec.calls.clear()
    UInputDevice("Rel only", rel_axes=[0])
    assert [c for c in rec.calls if c[:3] == ("ioctl", FD, 0x40045564)] == [("ioctl", FD, 0x40045564, EV_REL)]


def test_custom_path_is_opened(rec):
    UInputDevice("x", path="/dev/other")
    assert rec.calls[0][:2] == ("open", "/dev/other")


def test_long_name_is_cut_to_79_bytes_and_stays_terminated(rec):
    UInputDevice("x" * 100)
    setup = next(c[3] for c in rec.calls if c[2] == device.UI_DEV_SETUP)
    name = struct.unpack("=HHHH80sI", setup)[4]
    assert name == b"x" * 79 + b"\x00"


def test_write_packs_all_events_into_one_os_write(rec):
    dev = UInputDevice("x")
    rec.calls.clear()
    dev.write([(EV_KEY, 30, 1), (0, 0, 0)])
    expected = struct.pack("llHHi", 0, 0, 1, 30, 1) + struct.pack("llHHi", 0, 0, 0, 0, 0)
    assert len(expected) == 48
    assert rec.calls == [("write", FD, expected)]


def test_close_destroys_then_closes_and_is_safe_twice(rec):
    dev = UInputDevice("x")
    rec.calls.clear()
    dev.close()
    dev.close()
    assert rec.calls == [("ioctl", FD, 0x5502, 0), ("close", FD)]


def test_close_still_closes_the_descriptor_when_destroy_fails(rec):
    dev = UInputDevice("x")
    rec.calls.clear()
    rec.fail_destroy = True
    dev.close()
    assert rec.calls == [("ioctl", FD, 0x5502, 0), ("close", FD)]


def test_close_does_not_raise_when_the_descriptor_close_fails(rec):
    dev = UInputDevice("x")
    rec.fail_close = True
    dev.close()
    dev.close()


def test_write_after_close_is_an_input_error(rec):
    dev = UInputDevice("x")
    dev.close()
    rec.calls.clear()
    with pytest.raises(InputError):
        dev.write([(0, 0, 0)])
    assert rec.calls == []


def test_open_failure_becomes_input_error(rec):
    rec.fail_open = True
    with pytest.raises(InputError):
        UInputDevice("x")
    assert [c[0] for c in rec.calls] == ["open"]


def test_setup_failure_becomes_input_error_and_closes_the_descriptor(rec):
    rec.fail_ioctl_on = device.UI_DEV_SETUP
    with pytest.raises(InputError):
        UInputDevice("x", keys=[30])
    assert rec.calls[-1] == ("close", FD)
    assert not any(c[:3] == ("ioctl", FD, 0x5501) for c in rec.calls)


def test_create_failure_becomes_input_error_and_closes_the_descriptor(rec):
    rec.fail_ioctl_on = device.UI_DEV_CREATE
    with pytest.raises(InputError):
        UInputDevice("x")
    assert rec.calls[-1] == ("close", FD)


def test_write_failure_becomes_input_error(rec):
    dev = UInputDevice("x")
    rec.fail_write = True
    with pytest.raises(InputError):
        dev.write([(EV_KEY, 30, 1)])


def test_short_write_becomes_input_error(rec):
    dev = UInputDevice("x")
    rec.short_write = True
    with pytest.raises(InputError):
        dev.write([(EV_KEY, 30, 1), (0, 0, 0)])


def test_fake_device_records_events_in_order_and_closes():
    fake = FakeDevice()
    fake.write([(1, 30, 1), (0, 0, 0)])
    fake.write([(1, 30, 0), (0, 0, 0)])
    assert fake.events == [(1, 30, 1), (0, 0, 0), (1, 30, 0), (0, 0, 0)]
    assert not fake.closed
    fake.close()
    assert fake.closed


def test_fake_device_fail_raises_oserror_and_records_nothing():
    fake = FakeDevice()
    fake.fail = True
    with pytest.raises(OSError):
        fake.write([(1, 30, 1)])
    assert fake.events == []
