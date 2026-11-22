# Checks the parts of the device probe that need no Steam Deck: imports, logs, processes, avahi and typing.
import asyncio
import json
import string
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import spike_probe  # noqa: E402
from hotbar.input.device import FakeDevice, InputError  # noqa: E402
from hotbar.input.injector import Injector  # noqa: E402

EV_KEY = 1
KEY_ENTER = 28

BROWSE_LINES = (
    "+;wlan0;IPv4;steamdeck;_hotbar._tcp;local\n"
    '=;wlan0;IPv4;steamdeck;_hotbar._tcp;local;steamdeck.local;192.168.1.20;40123;"v=1" "pid=00ff"\n'
)
PROBE_LINE = "=;wlan0;IPv4;steamdeck\\032HotBar\\032probe;_hotbarprobe._tcp;local;steamdeck.local;192.168.1.20;9;\n"


def fake_injector():
    keyboard, pointer = FakeDevice(), FakeDevice()

    async def no_sleep(_seconds):
        return None

    return Injector(keyboard, pointer, sleep=no_sleep), keyboard


def write_selfcheck_log(folder: Path) -> None:
    folder.mkdir(parents=True)
    (folder / "2026-11-22.log").write_text(
        "[HotBar] INFO selfcheck python: 3.11.9\n"
        "[HotBar] INFO selfcheck hashlib_sha256: ok\n"
        "[HotBar] INFO selfcheck x25519_shared: 40 ms\n"
        "[HotBar] INFO selfcheck chacha20poly1305_seal_512: 3 ms\n"
        "[HotBar] INFO selfcheck effective_uid: 0\n"
        "[HotBar] INFO selfcheck uinput_writable: true\n"
        "[HotBar] INFO HotBar loaded\n"
    )


@pytest.fixture
def deck(tmp_path):
    """A fake machine: homebrew, proc and avahi folders, with no uinput."""
    homebrew, proc, services = tmp_path / "homebrew", tmp_path / "proc", tmp_path / "services"
    for folder in (homebrew, proc, services):
        folder.mkdir()
    argv = [
        "--homebrew", str(homebrew), "--proc-dir", str(proc), "--services-dir", str(services),
        "--uinput", str(tmp_path / "no-uinput"), "--timing-runs", "1",
    ]
    return type("Deck", (), {"homebrew": homebrew, "proc": proc, "services": services, "argv": argv})()


def test_plugin_imports_lists_the_stdlib_and_aiohttp_but_not_the_plugin_or_decky():
    modules = spike_probe.plugin_imports()
    for name in ("hashlib", "hmac", "secrets", "fcntl", "ctypes", "aiohttp", "asyncio"):
        assert name in modules
    assert "hotbar" not in modules and "decky" not in modules
    assert modules == sorted(modules)


def test_missing_modules_names_only_what_will_not_import():
    assert spike_probe.missing_modules(["os", "no_such_module_hotbar"]) == ["no_such_module_hotbar"]


def test_selfcheck_values_reads_names_and_values():
    values = spike_probe.selfcheck_values(["12:00 INFO selfcheck x25519_shared: 40 ms", "unrelated line"])
    assert values == {"x25519_shared": "40 ms"}


def test_log_dir_prefers_the_plugin_name_and_finds_another_folder(deck):
    assert spike_probe.find_log_dir(deck.homebrew) is None
    write_selfcheck_log(deck.homebrew / "logs" / "hotbar-decky")
    assert spike_probe.find_log_dir(deck.homebrew) == deck.homebrew / "logs" / "hotbar-decky"
    write_selfcheck_log(deck.homebrew / "logs" / "HotBar")
    assert spike_probe.find_log_dir(deck.homebrew) == deck.homebrew / "logs" / "HotBar"


def test_plugin_folder_is_found_by_its_manifest_name(deck):
    other = deck.homebrew / "plugins" / "Other"
    ours = deck.homebrew / "plugins" / "hotbar-1"
    for folder, name in ((other, "Other"), (ours, "HotBar")):
        folder.mkdir(parents=True)
        (folder / "plugin.json").write_text(json.dumps({"name": name}))
    (deck.homebrew / "plugins" / "Broken").mkdir()
    (deck.homebrew / "plugins" / "Broken" / "plugin.json").write_text("not json")
    assert spike_probe.find_plugin_folder(deck.homebrew) == ours


def test_loader_uids_reads_the_effective_uid_of_plugin_loader(deck):
    for pid, comm, uid in (("10", "PluginLoader", "0\t0\t0\t0"), ("11", "bash", "1000\t1000\t1000\t1000")):
        (deck.proc / pid).mkdir()
        (deck.proc / pid / "comm").write_text(comm + "\n")
        (deck.proc / pid / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\n")
    assert spike_probe.loader_uids(deck.proc) == [0]


def test_crypto_timings_cover_pairing_and_a_512_byte_message():
    timings = spike_probe.crypto_timings(1)
    assert set(timings) == {"pairing", "seal_512", "open_512"}
    assert all(median >= 0 and slowest >= median for median, slowest in timings.values())


def test_speed_section_estimates_a_decky_pairing_from_the_logged_key_agreement():
    lines = spike_probe.section_speed({"x25519_shared": "40 ms", "chacha20poly1305_seal_512": "3 ms"}, 1)
    assert "decky pairing estimate: about 80 ms (two X25519 operations)" in lines


def test_parse_browse_keeps_resolved_entries_and_unescapes_names():
    entries = spike_probe.parse_browse(BROWSE_LINES + PROBE_LINE)
    assert [e["name"] for e in entries] == ["steamdeck", "steamdeck HotBar probe"]
    assert entries[0]["address"] == "192.168.1.20" and entries[0]["port"] == "40123"
    assert entries[0]["txt"] == '"v=1" "pid=00ff"'


class FakeAvahi:
    """Answers avahi-browse and avahi-daemon --reload; the probe type appears once `visible_after` browses have run."""

    def __init__(self, services: Path, visible_after: int | None, reload_works: bool = True):
        self.services = services
        self.visible_after = visible_after
        self.reload_works = reload_works
        self.probe_browses = 0
        self.commands: list[list[str]] = []
        self.file_seen = False

    def __call__(self, cmd, _timeout):
        self.commands.append(cmd)
        if cmd[:2] == ["avahi-daemon", "--reload"]:
            if self.reload_works:
                self.visible_after = self.probe_browses
            return ""
        if cmd[-1] == spike_probe.PROBE_TYPE:
            self.file_seen |= (self.services / spike_probe.PROBE_FILE_NAME).is_file()
            self.probe_browses += 1
            visible = self.visible_after is not None and self.probe_browses > self.visible_after
            return PROBE_LINE if visible else ""
        return BROWSE_LINES


def test_pickup_test_sees_the_probe_file_without_a_reload_and_removes_it(deck):
    avahi = FakeAvahi(deck.services, visible_after=2)
    lines = spike_probe.pickup_test(deck.services, avahi, sleep=lambda _s: None)
    assert lines[0].startswith("pickup without restart: yes")
    assert avahi.file_seen
    assert ["avahi-daemon", "--reload"] not in avahi.commands
    assert list(deck.services.iterdir()) == []


def test_pickup_test_reloads_when_the_file_is_not_seen(deck):
    avahi = FakeAvahi(deck.services, visible_after=None)
    lines = spike_probe.pickup_test(deck.services, avahi, sleep=lambda _s: None)
    assert lines[0].startswith("pickup without restart: no")
    assert "has to ask avahi to reload" in lines[1]
    assert list(deck.services.iterdir()) == []


def test_pickup_test_reports_a_reload_that_does_not_help(deck):
    avahi = FakeAvahi(deck.services, visible_after=None, reload_works=False)
    lines = spike_probe.pickup_test(deck.services, avahi, sleep=lambda _s: None)
    assert lines[1] == "after avahi-daemon --reload: still not announced"


def test_pickup_test_skips_when_the_folder_is_not_writable(tmp_path):
    lines = spike_probe.pickup_test(tmp_path / "missing", FakeAvahi(tmp_path, 0), sleep=lambda _s: None)
    assert lines[0].startswith("pickup test skipped")


def test_discovery_resolves_locally_runs_pickup_and_prints_the_mac_commands(deck, monkeypatch):
    (deck.proc / "7").mkdir()
    (deck.proc / "7" / "comm").write_text("avahi-daemon\n")
    monkeypatch.setattr(spike_probe.shutil, "which", lambda _name: "/usr/bin/avahi-browse")
    avahi = FakeAvahi(deck.services, visible_after=0)
    out = "\n".join(spike_probe.section_discovery(deck.services, deck.proc, avahi, sleep=lambda _s: None))
    assert "avahi-daemon running: yes" in out
    assert "_hotbar._tcp on this Deck: steamdeck at 192.168.1.20:40123" in out
    assert "pickup without restart: yes" in out
    assert "dns-sd -B _hotbar._tcp local." in out


def test_type_tests_send_ascii_and_symbols_and_refuse_accents_and_emoji_whole():
    injector, keyboard = fake_injector()
    lines = asyncio.run(spike_probe.type_tests(injector))
    out = "\n".join(lines)
    assert "plain ASCII: sent HotBar probe 123" in out
    assert f"password symbols: sent {string.punctuation}" in out
    assert "accented letters: refused, nothing typed" in out and "é U+00E9" in out
    assert "emoji: refused, nothing typed" in out and "U+1F3AE" in out
    assert lines[-1] == f"expected on screen: HotBar probe 123 {string.punctuation}"
    pressed = [code for type_, code, value in keyboard.events if type_ == EV_KEY and value == 1]
    assert pressed and KEY_ENTER not in pressed


def test_typing_counts_down_after_opening_and_closes_the_devices(capsys):
    injector, keyboard = fake_injector()
    pauses = []
    lines = spike_probe.section_typing(3, pauses.append, lambda: injector)
    assert pauses == [1, 1, 1]
    assert "typing in 3" in capsys.readouterr().out
    assert keyboard.closed
    assert lines[-1].startswith("steam keyboard: not applicable")


def test_typing_without_input_device_is_skipped():
    def failing_open():
        raise InputError("no /dev/uinput")

    assert spike_probe.section_typing(3, lambda _s: None, failing_open)[0].startswith("typing test skipped")


def test_main_prints_every_section_and_reads_the_plugin_log(deck, capsys):
    write_selfcheck_log(deck.homebrew / "logs" / "HotBar")

    def refuse():
        raise AssertionError("must not open the input devices")

    assert spike_probe.main([*deck.argv, "--no-type"], runner=FakeAvahi(deck.services, 0), open_injector=refuse) == 0
    out = capsys.readouterr().out
    for title in ("1. Python modules", "2. Crypto speed", "3. Input device", "4. Typing", "5. Service discovery", "6. Logs"):
        assert f"== {title} ==" in out
    assert "decky python: 3.11.9" in out
    assert "plugin effective uid: 0" in out
    assert "plugin opened" in out and ": true" in out
    assert "plugin created its virtual keyboard and pointer: yes" in out
    assert f"log with the self-check lines: {deck.homebrew / 'logs' / 'HotBar' / '2026-11-22.log'}" in out


def test_main_without_a_plugin_log_says_what_is_unknown(deck, capsys):
    assert spike_probe.main([*deck.argv, "--no-type"], runner=FakeAvahi(deck.services, 0)) == 0
    out = capsys.readouterr().out
    assert "decky python: unknown" in out
    assert "self-check lines: not found" in out


def test_start_outcome_reads_the_last_start_up_line(tmp_path):
    log = tmp_path / "plugin.log"
    assert spike_probe.start_outcome(None).startswith("unknown")
    log.write_text("x HotBar loaded\nx could not open the virtual input devices\n")
    assert spike_probe.start_outcome(log).startswith("no")
    log.write_text("x could not open the virtual input devices\nx HotBar loaded\n")
    assert spike_probe.start_outcome(log).startswith("yes")
    log.write_text("x other\n")
    assert spike_probe.start_outcome(log).startswith("unknown")
