# Device probe for a Steam Deck: modules, crypto speed, /dev/uinput, typing, avahi discovery and the log path, in one run.
#
#   sudo python3 tools/spike_probe.py [--no-type] [--countdown SECONDS] [--homebrew DIR]
#
# Run it over SSH or in Konsole in Desktop Mode, with sudo so it has the plugin's privileges. It runs on the
# Deck's system Python. Decky runs the plugin with its own bundled Python, so for that interpreter the probe
# reads the self-check lines the plugin logs at start-up: install and start the plugin before running it.
# docs/spike-2.md is the runbook and the results table.
#
# Side effects: it writes and then removes /etc/avahi/services/hotbar-probe.service, asks avahi to reload
# only if that file is not picked up on its own, and at the end types four test lines into the focused
# window through the plugin's input code (never Enter) unless --no-type is given.
import argparse
import ast
import asyncio
import contextlib
import importlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import statistics
import string
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "py_modules"))
sys.path.insert(0, str(ROOT / "tools"))

import diagnose  # noqa: E402
from hotbar import constants as c  # noqa: E402
from hotbar import crypto, envelope  # noqa: E402
from hotbar.advertise import DEFAULT_SERVICES_DIR, SERVICE_FILE_NAME, SERVICE_TYPE  # noqa: E402
from hotbar.input.device import InputError  # noqa: E402
from hotbar.input.injector import Injector  # noqa: E402
from hotbar.input.keymap import char_supported  # noqa: E402
from hotbar.selfcheck import uinput_writable  # noqa: E402

Runner = Callable[[list[str], float], str | None]

PLUGIN_NAME = "HotBar"
DEFAULT_HOMEBREW = Path("/home/deck/homebrew")
LOADER_COMM = "PluginLoader"
TIMING_RUNS = 5
COUNTDOWN_S = 10
BROWSE_TIMEOUT_S = 10.0
PICKUP_ATTEMPTS = 10
PROBE_FILE_NAME = "hotbar-probe.service"
PROBE_TYPE = "_hotbarprobe._tcp"
PROBE_PORT = 9

TYPING_TESTS: tuple[tuple[str, str], ...] = (
    ("plain ASCII", "HotBar probe 123"),
    ("password symbols", string.punctuation),
    ("accented letters", "café naïve façade Ångström"),
    ("emoji", "🎮👍😀"),
)

_SELFCHECK = re.compile(r"\bselfcheck (\w+): (.*)$")
_AVAHI_ESCAPE = re.compile(r"\\(\d{3})")
_MS = re.compile(r"^(\d+) ms$")

_PROBE_TEMPLATE = """<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">%h HotBar probe</name>
  <service>
    <type>{type}</type>
    <port>{port}</port>
  </service>
</service-group>
"""


def run_command(cmd: list[str], timeout: float) -> str | None:
    """Stdout of `cmd`, or None if it is missing or failed. On a timeout, whatever it printed so far."""
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout
        return out.decode(errors="replace") if isinstance(out, bytes) else out
    except OSError:
        return None
    return done.stdout if done.returncode == 0 else None


def plugin_imports(root: Path = ROOT) -> list[str]:
    """Top-level modules that main.py and py_modules import, without the plugin's own and Decky's."""
    names: set[str] = set()
    for path in [root / "main.py", *sorted((root / "py_modules").rglob("*.py"))]:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return sorted(names - {"hotbar", "decky", "__future__"})


def missing_modules(modules: list[str]) -> list[str]:
    missing = []
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception:
            missing.append(name)
    return missing


def selfcheck_values(lines: list[str]) -> dict[str, str]:
    values = {}
    for line in lines:
        match = _SELFCHECK.search(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def find_plugin_folder(homebrew: Path) -> Path | None:
    try:
        manifests = sorted((homebrew / "plugins").glob("*/plugin.json"))
    except OSError:
        return None
    for manifest in manifests:
        try:
            if json.loads(manifest.read_text()).get("name") == PLUGIN_NAME:
                return manifest.parent
        except (OSError, ValueError, AttributeError):
            continue
    return None


def find_log_dir(homebrew: Path) -> Path | None:
    """The folder whose newest log holds the plugin's self-check lines, the expected one first."""
    logs = homebrew / "logs"
    try:
        others = sorted(p for p in logs.iterdir() if p.is_dir() and p.name != PLUGIN_NAME)
    except OSError:
        others = []
    for folder in [logs / PLUGIN_NAME, *others]:
        if diagnose.last_selfcheck_lines(folder):
            return folder
    return None


def newest_log(folder: Path) -> Path | None:
    try:
        logs = [p for p in folder.glob("*.log") if p.is_file()]
        return max(logs, key=lambda p: p.stat().st_mtime) if logs else None
    except OSError:
        return None


def import_errors(log: Path | None) -> list[str]:
    if log is None:
        return []
    try:
        text = log.read_text(errors="replace")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if "ModuleNotFoundError" in line or "ImportError" in line]


def loader_uids(proc_dir: Path) -> list[int]:
    """Effective uids of running Decky loader processes."""
    uids = set()
    try:
        entries = list(proc_dir.iterdir())
    except OSError:
        return []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() != LOADER_COMM:
                continue
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("Uid:"):
                    uids.add(int(line.split()[2]))
        except (OSError, ValueError, IndexError):
            continue
    return sorted(uids)


def _timed_ms(work: Callable[[], object], runs: int) -> tuple[float, float]:
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        work()
        times.append((time.perf_counter() - start) * 1000)
    return statistics.median(times), max(times)


def _pairing_work(phone_public: bytes) -> Callable[[], None]:
    """The plugin's side of one pairing: its key pair, the shared secret and the three derived keys."""
    salt = os.urandom(c.SECRET_LEN + 2 * c.PAIR_NONCE_LEN)

    def work() -> None:
        private = os.urandom(32)
        public = crypto.x25519_public(private)
        shared = crypto.x25519_shared(private, phone_public)
        suffix = phone_public + public + bytes(c.DEVICE_ID_LEN)
        for label in (c.LABEL_DEVICE_KEY, c.LABEL_CONFIRM_PHONE, c.LABEL_CONFIRM_PLUGIN):
            crypto.hkdf(shared, salt, label + suffix, 32)

    return work


def crypto_timings(runs: int) -> dict[str, tuple[float, float]]:
    """Median and slowest time in ms, in this Python, for one pairing and for sealing and opening a 512-byte message."""
    key = os.urandom(32)
    header = envelope.Header(
        c.VERSION, c.DIR_PHONE_TO_PLUGIN, bytes(c.DEVICE_ID_LEN), bytes(c.SENDER_ID_LEN), 1, os.urandom(c.SALT_LEN)
    )
    body = bytes(512)
    wire = envelope.seal(key, header, body)
    return {
        "pairing": _timed_ms(_pairing_work(crypto.x25519_public(os.urandom(32))), runs),
        "seal_512": _timed_ms(lambda: envelope.seal(key, header, body), runs),
        "open_512": _timed_ms(lambda: envelope.open_envelope(key, wire), runs),
    }


def parse_browse(output: str) -> list[dict[str, str]]:
    """Resolved services from `avahi-browse -p -r` output."""
    entries = []
    for line in output.splitlines():
        parts = line.split(";", 9)
        if parts[0] != "=" or len(parts) < 9:
            continue
        entries.append(
            {
                "interface": parts[1],
                "protocol": parts[2],
                "name": _AVAHI_ESCAPE.sub(lambda m: chr(int(m.group(1))), parts[3]),
                "host": parts[6],
                "address": parts[7],
                "port": parts[8],
                "txt": parts[9] if len(parts) > 9 else "",
            }
        )
    return entries


def browse(runner: Runner, service_type: str) -> list[dict[str, str]] | None:
    output = runner(["avahi-browse", "-p", "-r", "-t", service_type], BROWSE_TIMEOUT_S)
    return None if output is None else parse_browse(output)


def write_probe_file(services_dir: Path) -> Path:
    """Writes the probe service file the way the plugin writes its own: a temporary name, then a rename."""
    fd, tmp_name = tempfile.mkstemp(dir=services_dir, prefix=".hotbar-probe-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as tmp:
            tmp.write(_PROBE_TEMPLATE.format(type=PROBE_TYPE, port=PROBE_PORT))
            os.fchmod(tmp.fileno(), 0o644)
        path = services_dir / PROBE_FILE_NAME
        os.replace(tmp_name, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    return path


def _wait_for_probe(runner: Runner, sleep: Callable[[float], None]) -> float | None:
    start = time.monotonic()
    for attempt in range(PICKUP_ATTEMPTS):
        if attempt:
            sleep(1)
        if browse(runner, PROBE_TYPE):
            return time.monotonic() - start
    return None


def pickup_test(services_dir: Path, runner: Runner, sleep: Callable[[float], None]) -> list[str]:
    """Does avahi announce a service file written while it runs, without a restart?"""
    try:
        path = write_probe_file(services_dir)
    except OSError as exc:
        return [f"pickup test skipped: cannot write to {services_dir} ({type(exc).__name__}); run with sudo"]
    try:
        seen = _wait_for_probe(runner, sleep)
        if seen is not None:
            return [f"pickup without restart: yes, announced after about {seen:.0f} s"]
        lines = [f"pickup without restart: no, not announced within {PICKUP_ATTEMPTS} tries"]
        if runner(["avahi-daemon", "--reload"], BROWSE_TIMEOUT_S) is None:
            lines.append("avahi-daemon --reload: failed")
        elif _wait_for_probe(runner, sleep) is not None:
            lines.append("after avahi-daemon --reload: announced, so the plugin has to ask avahi to reload")
        else:
            lines.append("after avahi-daemon --reload: still not announced")
        return lines
    finally:
        with contextlib.suppress(OSError):
            path.unlink()


def section_modules(modules: list[str], frozen: dict[str, str], log: Path | None) -> list[str]:
    missing = missing_modules(modules)
    lines = [
        f"system python: {platform.python_version()} at {sys.executable}",
        f"modules the plugin imports: {', '.join(modules)}",
        f"missing in system python: {', '.join(missing) or 'none'}"
        + (" (Decky bundles aiohttp, so missing here is expected)" if missing == ["aiohttp"] else ""),
    ]
    if not frozen:
        lines.append("decky python: unknown, no self-check lines in the plugin log (start the plugin, then run again)")
        return lines
    lines.append(f"decky python: {frozen.get('python', 'not logged')}")
    for name in ("hashlib_sha256", "hmac", "secrets", "fcntl", "ctypes", "aiohttp"):
        lines.append(f"decky {name}: {frozen.get(name, 'not logged')}")
    lines.append("decky python loaded every module above: yes (the self-check runs after all of the plugin's imports)")
    errors = import_errors(log)
    if errors:
        lines.append("import errors in the plugin log:")
        lines.extend(f"  {line}" for line in errors[-5:])
    return lines


def section_speed(frozen: dict[str, str], runs: int) -> list[str]:
    lines = []
    for name, (median, slowest) in crypto_timings(runs).items():
        lines.append(f"system python {name}: {median:.0f} ms median, {slowest:.0f} ms slowest of {runs}")
    shared = frozen.get("x25519_shared")
    if shared is None:
        lines.append("decky python: unknown, no self-check lines in the plugin log")
        return lines
    lines.append(f"decky x25519_shared (one key agreement): {shared}")
    lines.append(f"decky chacha20poly1305_seal_512: {frozen.get('chacha20poly1305_seal_512', 'not logged')}")
    match = _MS.match(shared)
    if match:
        lines.append(f"decky pairing estimate: about {2 * int(match.group(1))} ms (two X25519 operations)")
    return lines


def start_outcome(log: Path | None) -> str:
    """How the plugin's last start in `log` went, from the lines main.py logs."""
    try:
        text = log.read_text(errors="replace") if log else ""
    except OSError:
        text = ""
    outcomes = {
        "HotBar loaded": "yes, the plugin started",
        "could not open the virtual input devices": "no, the plugin could not create its virtual devices",
    }
    last = max(outcomes, key=text.rfind)
    return outcomes[last] if text.rfind(last) >= 0 else "unknown, no start-up line in the plugin log"


def section_input(uinput_path: str, proc_dir: Path, frozen: dict[str, str], log: Path | None) -> list[str]:
    try:
        st = os.stat(uinput_path)
        lines = [f"{uinput_path}: {stat.filemode(st.st_mode)}, owner uid {st.st_uid}, group gid {st.st_gid}"]
    except OSError as exc:
        lines = [f"{uinput_path}: cannot stat ({type(exc).__name__})"]
    euid = os.geteuid()
    lines.append(f"this probe's effective uid: {euid}, {uinput_path} writable: {'yes' if uinput_writable(uinput_path) else 'no'}")
    uids = loader_uids(proc_dir)
    lines.append(f"decky loader effective uid: {', '.join(map(str, uids)) if uids else 'loader not running'}")
    if frozen:
        lines.append(f"plugin effective uid: {frozen.get('effective_uid', 'not logged')}")
        lines.append(f"plugin opened {uinput_path}: {frozen.get('uinput_writable', 'not logged')}")
        lines.append(f"plugin created its virtual keyboard and pointer: {start_outcome(log)}")
    else:
        lines.append("plugin uid and uinput access: unknown, no self-check lines in the plugin log")
    return lines


def section_discovery(services_dir: Path, proc_dir: Path, runner: Runner, sleep: Callable[[float], None]) -> list[str]:
    running = diagnose.avahi_running(proc_dir)
    lines = [
        f"avahi-daemon running: {'yes' if running else 'no'}",
        f"{services_dir / SERVICE_FILE_NAME}: {diagnose.service_file_state(services_dir)}",
    ]
    if not running:
        return lines
    if shutil.which("avahi-browse") is None:
        lines.append("avahi-browse not installed: local resolve and pickup test skipped")
    else:
        found = browse(runner, SERVICE_TYPE)
        if not found:
            lines.append(f"{SERVICE_TYPE} on this Deck: not resolved")
        else:
            for entry in found:
                lines.append(
                    f"{SERVICE_TYPE} on this Deck: {entry['name']} at {entry['address']}:{entry['port']} "
                    f"({entry['interface']} {entry['protocol']}) {entry['txt']}"
                )
        lines.extend(pickup_test(services_dir, runner, sleep))
    host = socket.gethostname() or "steamdeck"
    lines += [
        "from a Mac on the same network, run these and note what they print:",
        f"  dns-sd -B {SERVICE_TYPE} local.",
        f'  dns-sd -L "{host}" {SERVICE_TYPE} local.',
    ]
    return lines


def section_logs(homebrew: Path, log_dir: Path | None) -> list[str]:
    expected = homebrew / "logs" / PLUGIN_NAME
    folder = find_plugin_folder(homebrew)
    lines = [
        f"plugin folder: {folder if folder else 'not found under ' + str(homebrew / 'plugins')}",
        f"expected log folder {expected}: {'exists' if expected.is_dir() else 'missing'}",
    ]
    if log_dir is None:
        lines.append(f"self-check lines: not found in any folder under {homebrew / 'logs'}")
    else:
        log = newest_log(log_dir)
        lines.append(f"log with the self-check lines: {log if log else log_dir}")
    lines.append("decky loader log: journalctl -b -u plugin_loader --no-pager")
    return lines


async def type_tests(injector: Injector, tests: tuple[tuple[str, str], ...] = TYPING_TESTS) -> list[str]:
    """Types each test line with no Enter, a space between lines that went through. A line with a character
    the plugin cannot type is refused whole, as the plugin refuses it, and nothing of it is typed."""
    lines = []
    typed: list[str] = []
    for label, text in tests:
        try:
            if typed:
                await injector.type_text(" ", None, False)
            await injector.type_text(text, None, False)
        except ValueError:
            refused = dict.fromkeys(ch for ch in text if not char_supported(ch))
            listed = " ".join(f"{ch} U+{ord(ch):04X}" for ch in refused)
            lines.append(f"{label}: refused, nothing typed (cannot type: {listed})")
        else:
            typed.append(text)
            lines.append(f"{label}: sent {text}")
    lines.append(f"expected on screen: {' '.join(typed)}")
    return lines


def section_typing(countdown: int, sleep: Callable[[float], None], open_injector: Callable[[], Injector]) -> list[str]:
    try:
        injector = open_injector()
    except InputError:
        return ["typing test skipped: could not open the virtual input devices (run with sudo)"]
    try:
        # The countdown also gives the desktop time to pick up the new virtual keyboard.
        for left in range(countdown, 0, -1):
            print(f"typing in {left}... put the cursor in a text field on the Deck", flush=True)
            sleep(1)
        lines = asyncio.run(type_tests(injector))
    except InputError:
        lines = ["typing test failed: could not write to the virtual input devices"]
    finally:
        injector.close()
    lines.append("steam keyboard: not applicable, the plugin types only through /dev/uinput")
    return lines


def _print_section(title: str, lines: list[str]) -> None:
    print(f"\n== {title} ==", flush=True)
    for line in lines:
        print(line, flush=True)


def main(
    argv: list[str] | None = None,
    *,
    runner: Runner = run_command,
    sleep: Callable[[float], None] = time.sleep,
    open_injector: Callable[[], Injector] = Injector.open_uinput,
) -> int:
    parser = argparse.ArgumentParser(description="Probe this Steam Deck for the facts the HotBar plugin depends on.")
    parser.add_argument("--no-type", action="store_true", help="skip the typing test")
    parser.add_argument("--countdown", type=int, default=COUNTDOWN_S, help="seconds before typing starts")
    parser.add_argument("--homebrew", type=Path, default=DEFAULT_HOMEBREW)
    parser.add_argument("--uinput", default="/dev/uinput")
    parser.add_argument("--services-dir", type=Path, default=DEFAULT_SERVICES_DIR)
    parser.add_argument("--proc-dir", type=Path, default=Path("/proc"))
    parser.add_argument("--timing-runs", type=int, default=TIMING_RUNS)
    args = parser.parse_args(argv)

    log_dir = find_log_dir(args.homebrew)
    frozen = selfcheck_values(diagnose.last_selfcheck_lines(log_dir) or []) if log_dir else {}
    log = newest_log(log_dir) if log_dir else None

    print(f"HotBar device probe, {time.strftime('%Y-%m-%d %H:%M:%S')}, {platform.platform()}", flush=True)
    _print_section("1. Python modules", section_modules(plugin_imports(), frozen, log))
    _print_section("2. Crypto speed", section_speed(frozen, max(1, args.timing_runs)))
    _print_section("3. Input device", section_input(args.uinput, args.proc_dir, frozen, log))
    _print_section("5. Service discovery", section_discovery(args.services_dir, args.proc_dir, runner, sleep))
    _print_section("6. Logs", section_logs(args.homebrew, log_dir))
    if args.no_type:
        _print_section("4. Typing", ["skipped (--no-type)"])
    else:
        print("\n== 4. Typing ==", flush=True)
        for line in section_typing(max(0, args.countdown), sleep, open_injector):
            print(line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
