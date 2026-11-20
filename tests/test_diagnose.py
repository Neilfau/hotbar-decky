# Checks the SSH diagnostic tool on a machine without uinput or avahi, and its opt-in typed test line.
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import diagnose  # noqa: E402
from hotbar.input.device import FakeDevice, InputError  # noqa: E402
from hotbar.input.injector import Injector  # noqa: E402

KEY_ENTER = 28
EV_KEY = 1


@pytest.fixture
def paths(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    services, logs = tmp_path / "services", tmp_path / "logs"
    services.mkdir()
    logs.mkdir()
    argv = [
        "--uinput", str(tmp_path / "no-uinput"), "--services-dir", str(services),
        "--log-dir", str(logs), "--proc-dir", str(proc),
    ]
    return type("Paths", (), {"argv": argv, "proc": proc, "services": services, "logs": logs})()


def fake_injector():
    keyboard, pointer = FakeDevice(), FakeDevice()

    async def no_sleep(_seconds):
        return None

    return Injector(keyboard, pointer, sleep=no_sleep), keyboard


def test_report_without_uinput_avahi_service_file_or_log(paths, capsys):
    assert diagnose.main(paths.argv) == 0
    out = capsys.readouterr().out
    assert "no-uinput writable: no" in out
    assert "avahi-daemon running: no" in out
    assert "hotbar.service: absent" in out
    assert "plugin log not readable" in out


def test_report_sees_avahi_service_file_and_self_check_lines(paths, capsys):
    (paths.proc / "123").mkdir()
    (paths.proc / "123" / "comm").write_text("avahi-daemon\n")
    (paths.proc / "self").mkdir()
    (paths.services / "hotbar.service").write_text("<type>_hotbar._tcp</type>")
    (paths.logs / "plugin.log").write_text(
        "other line\n12:00 INFO selfcheck python: 3.11.4\n12:00 INFO selfcheck uinput_writable: true\n"
    )
    assert diagnose.main(paths.argv) == 0
    out = capsys.readouterr().out
    assert "avahi-daemon running: yes" in out
    assert "hotbar.service: present" in out
    assert "selfcheck uinput_writable: true" in out
    assert "other line" not in out


def test_no_typing_without_the_flag(paths):
    def refuse():
        raise AssertionError("must not open the input devices")

    assert diagnose.main(paths.argv, open_injector=refuse) == 0


def test_type_test_counts_down_then_types_every_character_once_and_no_enter(paths, capsys):
    injector, keyboard = fake_injector()
    pauses = []
    assert diagnose.main([*paths.argv, "--type-test"], sleep=pauses.append, open_injector=lambda: injector) == 0
    assert pauses == [1] * 5
    out = capsys.readouterr().out
    assert out.index("typing in 5") < out.index("type test: typed")
    codes = [code for type_, code, value in keyboard.events if type_ == EV_KEY and value == 1]
    assert codes and KEY_ENTER not in codes
    assert keyboard.closed


def test_the_test_line_covers_space_to_tilde_without_enter():
    assert diagnose.TEST_LINE == "".join(map(chr, range(0x20, 0x7F)))
    assert "\n" not in diagnose.TEST_LINE and "\r" not in diagnose.TEST_LINE


def test_type_test_without_input_device_reports_and_fails(paths, capsys):
    def failing_open():
        raise InputError("no /dev/uinput")

    assert diagnose.main([*paths.argv, "--type-test"], sleep=lambda _s: None, open_injector=failing_open) == 1
    assert "type test skipped" in capsys.readouterr().out
