# Decky backend entry point for the HotBar plugin: opens the store and the input device, runs the server, answers the panel.
import asyncio
import socket
import sys
from pathlib import Path

import decky

_PLUGIN_DIR = Path(getattr(decky, "DECKY_PLUGIN_DIR", None) or Path(__file__).resolve().parent)
if str(_PLUGIN_DIR / "py_modules") not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR / "py_modules"))

from hotbar import advertise, selfcheck  # noqa: E402
from hotbar.input.device import InputError  # noqa: E402
from hotbar.input.injector import Injector  # noqa: E402
from hotbar.netutil import default_local_ip  # noqa: E402
from hotbar.server import HotBarServer  # noqa: E402
from hotbar.store import DeviceStore, StoreError  # noqa: E402

BIND_HOST = "0.0.0.0"
UINPUT_PATH = "/dev/uinput"
AVAHI_SERVICES_DIR = advertise.DEFAULT_SERVICES_DIR


class _State:
    """What the plugin holds between RPC calls. Decky passes `self` as the class or as an instance
    depending on its version, so nothing lives on it."""

    def __init__(self) -> None:
        self.store: DeviceStore | None = None
        self.injector: Injector | None = None
        self.server: HotBarServer | None = None
        self.error: str | None = None
        self.emits: set[asyncio.Task] = set()


_state = _State()


def _panel_state() -> dict:
    if _state.server is not None:
        return _state.server.state()
    return {"listening": False, "error": _state.error or "Not started", "devices": [], "pairing": None}


def _announce() -> None:
    task = asyncio.get_running_loop().create_task(_emit(_panel_state()))
    _state.emits.add(task)
    task.add_done_callback(_state.emits.discard)


async def _emit(state: dict) -> None:
    try:
        await decky.emit("hotbar_state", state)
    except Exception as exc:
        decky.logger.warning(f"could not send the state to the panel: {type(exc).__name__}")


class Plugin:
    # Runs in a task when the plugin is loaded.
    async def _main(self):
        _state.error = _state.server = None
        selfcheck.run(decky.logger, uinput_path=UINPUT_PATH, services_dir=AVAHI_SERVICES_DIR)
        advertise.withdraw(AVAHI_SERVICES_DIR, decky.logger)  # a file left by a crash names a dead port
        try:
            _state.store = DeviceStore(Path(decky.DECKY_PLUGIN_SETTINGS_DIR) / "devices.json")
        except StoreError:
            _state.error = "Key storage unavailable"
            decky.logger.error("could not open the device file")
            return
        if _state.store.recovered_from_corruption:
            decky.logger.warning("the device file was corrupt and has been set aside; no devices are paired")
        try:
            _state.injector = Injector.open_uinput()
        except InputError:
            _state.error = "Input device unavailable"
            decky.logger.error("could not open the virtual input devices")
            return
        _state.server = HotBarServer(
            store=_state.store,
            injector=_state.injector,
            logger=decky.logger,
            hostname=socket.gethostname() or "steamdeck",
            local_ip=default_local_ip,
            on_change=_announce,
            bind_host=BIND_HOST,
        )
        await _state.server.start()
        if _state.server.port is not None:
            advertise.publish(AVAHI_SERVICES_DIR, _state.server.port, _state.store.plugin_id, decky.logger)
        decky.logger.info("HotBar loaded")

    # Runs when the plugin is stopped but not removed.
    async def _unload(self):
        advertise.withdraw(AVAHI_SERVICES_DIR, decky.logger)
        if _state.server is not None:
            await _state.server.stop()
        if _state.injector is not None:
            _state.injector.close()
        decky.logger.info("HotBar unloaded")

    # Runs after _unload when the plugin is uninstalled.
    async def _uninstall(self):
        advertise.withdraw(AVAHI_SERVICES_DIR, decky.logger)

    # Runs before _main to migrate old data.
    async def _migration(self):
        pass

    async def get_state(self) -> dict:
        return _panel_state()

    async def start_pairing(self) -> dict:
        return _state.server.start_pairing() if _state.server else _panel_state()

    async def cancel_pairing(self) -> dict:
        return _state.server.cancel_pairing() if _state.server else _panel_state()

    async def remove_device(self, device_id: str) -> dict:
        return await _state.server.remove_device(device_id) if _state.server else _panel_state()

    async def remove_all_devices(self) -> dict:
        return await _state.server.remove_all_devices() if _state.server else _panel_state()
