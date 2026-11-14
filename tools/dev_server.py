# Runs the backend on a development machine with fake input devices, for local testing only.
#
#   uv run --python 3.14 --with aiohttp python tools/dev_server.py [--port N] [--state-dir DIR]
#
# It prints the pairing link to stdout, so it must never run anywhere the output is shared. After that
# it prints one line per injected action with the action kind and the number of events, nothing else.
# A fresh pairing link is printed whenever a session ends. Without a private network address the link
# uses 127.0.0.1, which only a client on this machine can reach.
import argparse
import asyncio
import contextvars
import logging
import socket
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "py_modules"))

from hotbar.input.device import FakeDevice  # noqa: E402
from hotbar.input.injector import Injector  # noqa: E402
from hotbar.netutil import default_local_ip  # noqa: E402
from hotbar.server import HotBarServer  # noqa: E402
from hotbar.store import DeviceStore  # noqa: E402

# Counts the events written while one action runs; the injector runs it in the calling task's context.
_action_events: contextvars.ContextVar[list[int] | None] = contextvars.ContextVar("action_events", default=None)


class CountingDevice(FakeDevice):
    def write(self, events):
        counter = _action_events.get()
        if counter is not None:
            counter[0] += len(events)


class ReportingInjector(Injector):
    async def _reported(self, kind: str, action) -> None:
        counter = [0]
        token = _action_events.set(counter)
        try:
            await action
        finally:
            _action_events.reset(token)
        print(f"{kind}: {counter[0]} events", flush=True)

    async def press(self, *args):
        await self._reported("press", super().press(*args))

    async def type_text(self, *args):
        await self._reported("type", super().type_text(*args))

    async def move(self, *args):
        await self._reported("move", super().move(*args))

    async def scroll(self, *args):
        await self._reported("scroll", super().scroll(*args))

    async def button(self, *args):
        await self._reported("button", super().button(*args))


async def run(port: int | None, state_dir: Path) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    injector = ReportingInjector(CountingDevice(), CountingDevice())
    server: HotBarServer

    def renew() -> None:
        state = server.state()
        if state["pairing"] is not None or not state["listening"]:
            return
        pairing = server.start_pairing()["pairing"]
        if pairing is None:
            print("pairing unavailable: " + str(server.state()["error"]), flush=True)
            return
        print(pairing["uri"], flush=True)

    server = HotBarServer(
        store=DeviceStore(state_dir / "devices.json"),
        injector=injector,
        logger=logging.getLogger("hotbar-dev"),
        hostname=socket.gethostname() or "dev",
        local_ip=lambda: default_local_ip() or "127.0.0.1",
        # Called from inside server code, so the renewal runs on the next loop turn.
        on_change=lambda: asyncio.get_running_loop().call_soon(renew),
        port=port,
        bind_host="0.0.0.0",
    )
    await server.start()
    if not server.state()["listening"]:
        print("could not listen: " + str(server.state()["error"]), flush=True)
        return
    print(f"listening on port {server.port}", flush=True)
    renew()
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the HotBar backend with fake input devices.")
    parser.add_argument("--port", type=int, default=None, help="TCP port; default is the stored or built-in port")
    parser.add_argument("--state-dir", type=Path, default=None, help="where devices.json lives; default is a temporary directory")
    args = parser.parse_args()
    try:
        if args.state_dir is not None:
            asyncio.run(run(args.port, args.state_dir))
        else:
            with tempfile.TemporaryDirectory() as tmp:
                asyncio.run(run(args.port, Path(tmp)))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
