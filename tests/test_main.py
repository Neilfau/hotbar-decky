# Checks the plugin lifecycle in main.py against a real server, with the Decky module and the input devices faked.
import asyncio
import functools
import logging
import os
import time

import aiohttp
import decky
import pytest

import main
from hotbar.input.device import FakeDevice, InputError
from hotbar.input.injector import Injector
from hotbar.store import StoreError
from phone_client import PhonePairing

STORE_FAILED = {"listening": False, "error": "Key storage unavailable", "devices": [], "pairing": None}


def run(test):
    """Runs an async test body under asyncio.run, with a timeout so a hang fails instead of stalling."""

    @functools.wraps(test)
    def wrapper(*args, **kwargs):
        asyncio.run(asyncio.wait_for(test(*args, **kwargs), 30))

    return wrapper


async def until(condition):
    deadline = time.monotonic() + 5
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        await asyncio.sleep(0.005)


@pytest.fixture
def decky_env(tmp_path, monkeypatch):
    """Points the plugin at a temporary settings directory, fake input devices and loopback."""
    env = type("Env", (), {})()
    env.emitted = []
    env.keyboard, env.pointer = FakeDevice(), FakeDevice()

    async def emit(event, *args):
        env.emitted.append((event, args))

    monkeypatch.setattr(decky, "DECKY_PLUGIN_SETTINGS_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(decky, "emit", emit, raising=False)
    monkeypatch.setattr(main, "_state", main._State())
    monkeypatch.setattr(main, "BIND_HOST", "127.0.0.1")
    env.services = tmp_path / "avahi"
    env.services.mkdir()
    monkeypatch.setattr(main, "AVAHI_SERVICES_DIR", env.services)
    monkeypatch.setattr(main, "UINPUT_PATH", str(tmp_path / "no-uinput"))
    monkeypatch.setattr(main, "default_local_ip", lambda: "127.0.0.1")
    monkeypatch.setattr(Injector, "open_uinput", classmethod(lambda cls: cls(env.keyboard, env.pointer)))
    return env


def test_main_exposes_plugin_class():
    assert isinstance(main.Plugin, type)


@run
async def test_plugin_pairs_a_phone_and_unload_releases_everything(decky_env):
    plugin = main.Plugin()
    await plugin._main()
    try:
        state = await plugin.get_state()
        assert (state["listening"], state["error"], state["devices"], state["pairing"]) == (True, None, [], None)

        uri = (await plugin.start_pairing())["pairing"]["uri"]
        phone = PhonePairing(uri, "Test Phone", os.urandom(32), os.urandom(16))
        base = f"http://127.0.0.1:{main._state.server.port}"
        async with aiohttp.ClientSession() as http:
            async with http.post(f"{base}/v1/pair", json=phone.pair_request()) as response:
                assert response.status == 200
                confirm = phone.on_pair_response(await response.json())
            async with http.post(f"{base}/v1/pair/confirm", json=confirm) as response:
                assert response.status == 200

        state = await plugin.get_state()
        assert [d["name"] for d in state["devices"]] == ["Test Phone"]
        # Every change reaches the panel as one state argument under the event the panel listens to.
        await until(lambda: decky_env.emitted and decky_env.emitted[-1][1][0]["devices"] == state["devices"])
        assert {event for event, _ in decky_env.emitted} == {"hotbar_state"}
        assert all(len(args) == 1 for _, args in decky_env.emitted)

        assert (await plugin.remove_device(phone.device_id.hex()))["devices"] == []
        await plugin.start_pairing()
        assert (await plugin.cancel_pairing())["pairing"] is None
        assert (await plugin.remove_all_devices())["devices"] == []
    finally:
        port = main._state.server.port
        await plugin._unload()
    assert decky_env.keyboard.closed and decky_env.pointer.closed
    with pytest.raises(aiohttp.ClientConnectionError):
        async with aiohttp.ClientSession() as http:
            await http.post(f"http://127.0.0.1:{port}/v1/challenge")


@run
async def test_unusable_key_storage_is_reported_and_methods_still_answer(decky_env, monkeypatch):
    def failing_store(_path):
        raise StoreError("cannot create the settings directory")

    monkeypatch.setattr(main, "DeviceStore", failing_store)
    plugin = main.Plugin()
    await plugin._main()
    assert await plugin.get_state() == STORE_FAILED
    assert await plugin.start_pairing() == STORE_FAILED
    assert await plugin.cancel_pairing() == STORE_FAILED
    assert await plugin.remove_device("00" * 16) == STORE_FAILED
    assert await plugin.remove_all_devices() == STORE_FAILED
    await plugin._unload()


@run
async def test_missing_input_device_is_reported_and_nothing_listens(decky_env, monkeypatch):
    def failing_open(_cls):
        raise InputError("no /dev/uinput")

    monkeypatch.setattr(Injector, "open_uinput", classmethod(failing_open))
    plugin = main.Plugin()
    await plugin._main()
    assert await plugin.get_state() == {**STORE_FAILED, "error": "Input device unavailable"}
    assert (await plugin.start_pairing())["pairing"] is None
    await plugin._unload()


@run
async def test_unload_before_main_does_nothing(decky_env):
    await main.Plugin()._unload()
    assert (await main.Plugin().get_state())["error"] == "Not started"


@run
async def test_panel_event_failure_is_logged_by_class_name_only(decky_env, monkeypatch, caplog):
    async def failing_emit(event, *args):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(decky, "emit", failing_emit, raising=False)
    plugin = main.Plugin()
    await plugin._main()
    try:
        with caplog.at_level(logging.INFO, logger="decky-test"):
            assert (await plugin.start_pairing())["pairing"] is not None
            await until(lambda: any("RuntimeError" in r.getMessage() for r in caplog.records))
        assert "secret detail" not in caplog.text
    finally:
        await plugin._unload()


@run
async def test_start_publishes_the_service_file_and_unload_removes_it(decky_env):
    plugin = main.Plugin()
    await plugin._main()
    try:
        text = (decky_env.services / "hotbar.service").read_text()
        assert f"<port>{main._state.server.port}</port>" in text
        assert f"pid={main._state.store.plugin_id.hex()}" in text
    finally:
        await plugin._unload()
    assert list(decky_env.services.iterdir()) == []


@run
async def test_uninstall_removes_the_service_file(decky_env):
    plugin = main.Plugin()
    await plugin._main()
    try:
        assert (decky_env.services / "hotbar.service").exists()
    finally:
        await plugin._unload()
    (decky_env.services / "hotbar.service").write_text("left behind")
    await plugin._uninstall()
    assert list(decky_env.services.iterdir()) == []


@run
async def test_missing_services_folder_logs_one_warning_and_the_plugin_still_listens(decky_env, monkeypatch, caplog):
    monkeypatch.setattr(main, "AVAHI_SERVICES_DIR", decky_env.services / "absent")
    plugin = main.Plugin()
    with caplog.at_level(logging.INFO, logger="decky-test"):
        await plugin._main()
    try:
        assert (await plugin.get_state())["listening"] is True
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "service file" in r.getMessage()]
        assert warnings == ["could not publish the service file: FileNotFoundError"]
    finally:
        await plugin._unload()


@run
async def test_start_logs_the_self_check_once(decky_env, caplog):
    plugin = main.Plugin()
    with caplog.at_level(logging.INFO, logger="decky-test"):
        await plugin._main()
    await plugin._unload()
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("selfcheck ")]
    assert sum(line.startswith("selfcheck python:") for line in lines) == 1
    assert "selfcheck uinput_writable: false" in lines


@run
async def test_nothing_is_published_when_the_input_device_is_missing(decky_env, monkeypatch):
    def failing_open(_cls):
        raise InputError("no /dev/uinput")

    monkeypatch.setattr(Injector, "open_uinput", classmethod(failing_open))
    plugin = main.Plugin()
    await plugin._main()
    assert list(decky_env.services.iterdir()) == []
    await plugin._unload()
