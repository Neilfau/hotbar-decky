# Checks a Steam Deck over SSH for what the plugin needs: root, /dev/uinput, avahi and the service file. Reads only; --type-test also types one line.
#
#   sudo python3 tools/diagnose.py [--type-test] [--uinput PATH] [--services-dir DIR] [--log-dir DIR]
#
# Run it with sudo so it has the same privileges as the plugin. This is the Deck's system Python, not the
# interpreter Decky runs the plugin with, so module and crypto results come from the plugin's own
# self-check lines in its log, which this tool prints when the log is readable.
#
# --type-test waits 5 seconds, then types the characters from space to tilde once through the plugin's own
# input code and never presses Enter. Put the cursor in a text field before the countdown ends.
import argparse
import asyncio
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "py_modules"))

from hotbar.advertise import DEFAULT_SERVICES_DIR, SERVICE_FILE_NAME  # noqa: E402
from hotbar.input.device import InputError  # noqa: E402
from hotbar.input.injector import Injector  # noqa: E402
from hotbar.selfcheck import PREFIX, uinput_writable  # noqa: E402

DEFAULT_LOG_DIR = Path("/home/deck/homebrew/logs/HotBar")
COUNTDOWN_S = 5
TEST_LINE = "".join(chr(code) for code in range(0x20, 0x7F))
SELFCHECK_LINES_MAX = 12


def avahi_running(proc_dir: Path) -> bool:
    try:
        entries = list(proc_dir.iterdir())
    except OSError:
        return False
    for entry in entries:
        if entry.name.isdigit():
            try:
                if (entry / "comm").read_text().strip().startswith("avahi-daemon"):
                    return True
            except OSError:
                continue
    return False


def service_file_state(services_dir: Path) -> str:
    path = services_dir / SERVICE_FILE_NAME
    try:
        text = path.read_text()
    except OSError:
        return "absent"
    return "present" if "_hotbar._tcp" in text else "present but unexpected content"


def last_selfcheck_lines(log_dir: Path) -> list[str] | None:
    try:
        logs = sorted((p for p in log_dir.glob("*.log") if p.is_file()), key=lambda p: p.stat().st_mtime)
        if not logs:
            return None
        lines = [line.strip() for line in logs[-1].read_text(errors="replace").splitlines() if f" {PREFIX} " in line]
    except OSError:
        return None
    return lines[-SELFCHECK_LINES_MAX:]


def report(uinput_path: str, services_dir: Path, log_dir: Path, proc_dir: Path) -> list[str]:
    lines = [
        f"effective uid: {os.geteuid()}" + (" (root)" if os.geteuid() == 0 else " (not root; run with sudo)"),
        f"{uinput_path} writable: {'yes' if uinput_writable(uinput_path) else 'no'}",
        f"avahi-daemon running: {'yes' if avahi_running(proc_dir) else 'no'}",
        f"{services_dir / SERVICE_FILE_NAME}: {service_file_state(services_dir)}",
    ]
    found = last_selfcheck_lines(log_dir)
    if found is None:
        lines.append(f"plugin log not readable in {log_dir}")
    elif not found:
        lines.append(f"no self-check lines in the newest log in {log_dir}")
    else:
        lines.append("plugin self-check lines:")
        lines.extend(f"  {line}" for line in found)
    return lines


async def type_test(injector: Injector) -> None:
    try:
        await injector.type_text(TEST_LINE, None, False)
    finally:
        injector.close()


def main(
    argv: list[str] | None = None,
    *,
    sleep: Callable[[float], None] = time.sleep,
    open_injector: Callable[[], Injector] = Injector.open_uinput,
) -> int:
    parser = argparse.ArgumentParser(description="Check this machine for what the HotBar plugin needs.")
    parser.add_argument("--type-test", action="store_true", help="after a countdown, type the printable ASCII characters once")
    parser.add_argument("--uinput", default="/dev/uinput")
    parser.add_argument("--services-dir", type=Path, default=DEFAULT_SERVICES_DIR)
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    parser.add_argument("--proc-dir", type=Path, default=Path("/proc"))
    args = parser.parse_args(argv)

    print("\n".join(report(args.uinput, args.services_dir, args.log_dir, args.proc_dir)), flush=True)
    if not args.type_test:
        return 0
    try:
        injector = open_injector()
    except InputError:
        print("type test skipped: could not open the virtual input devices", flush=True)
        return 1
    for left in range(COUNTDOWN_S, 0, -1):
        print(f"typing in {left}...", flush=True)
        sleep(1)
    try:
        asyncio.run(type_test(injector))
    except InputError:
        print("type test failed: could not write to the virtual input devices", flush=True)
        return 1
    print("type test: typed space to tilde, no Enter", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
