# Tests for the device key file: permissions, durability, failure handling and recovery.
import json
import os

import pytest

from hotbar.store import Device, DeviceStore, StoreError


def device(n: int, name: str = "Phone") -> Device:
    return Device(bytes([n]) * 16, bytes([n + 100]) * 32, f"{name} {n}", 1_700_000_000 + n)


def mode(path) -> int:
    return path.stat().st_mode & 0o777


@pytest.fixture
def path(tmp_path):
    return tmp_path / "settings" / "devices.json"


def test_creates_the_file_with_owner_only_permissions(path):
    store = DeviceStore(path)
    assert mode(path) == 0o600
    assert len(store.plugin_id) == 16
    assert store.devices() == [] and store.port is None
    assert store.recovered_from_corruption is False


def test_plugin_id_comes_from_the_injected_random(path):
    assert DeviceStore(path, random=lambda n: bytes([7]) * n).plugin_id == bytes([7]) * 16


def test_creates_a_missing_parent_directory(tmp_path):
    nested = tmp_path / "a" / "b" / "devices.json"
    DeviceStore(nested)
    assert nested.exists() and mode(nested) == 0o600


def test_plugin_id_is_stable_across_reloads(path):
    first = DeviceStore(path)
    assert DeviceStore(path).plugin_id == first.plugin_id


def test_devices_round_trip_in_creation_order(path):
    store = DeviceStore(path)
    for n in (3, 1, 2):
        store.add(device(n))
    assert mode(path) == 0o600
    reloaded = DeviceStore(path)
    assert reloaded.devices() == [device(3), device(1), device(2)]
    assert reloaded.get(device(1).device_id) == device(1)
    assert reloaded.get(bytes(16)) is None


def test_file_holds_lower_case_hex(path):
    DeviceStore(path).add(device(5))
    doc = json.loads(path.read_text())
    assert doc["pluginId"] == doc["pluginId"].lower() and len(doc["pluginId"]) == 32
    assert doc["devices"][0]["deviceKey"] == device(5).key.hex()
    assert doc["devices"][0]["deviceId"] == device(5).device_id.hex()


def test_remove_deletes_only_that_device_and_its_key_leaves_the_file(path):
    store = DeviceStore(path)
    store.add(device(1))
    store.add(device(2))
    assert store.remove(device(1).device_id) is True
    assert store.get(device(1).device_id) is None
    assert store.remove(device(1).device_id) is False
    assert DeviceStore(path).devices() == [device(2)]
    assert device(1).key.hex() not in path.read_text()
    assert mode(path) == 0o600


def test_remove_all_keeps_the_plugin_id(path):
    store = DeviceStore(path)
    store.add(device(1))
    store.add(device(2))
    store.remove_all()
    reloaded = DeviceStore(path)
    assert reloaded.devices() == []
    assert reloaded.plugin_id == store.plugin_id


def test_port_persists(path):
    store = DeviceStore(path)
    store.set_port(48321)
    assert store.port == 48321
    assert DeviceStore(path).port == 48321


@pytest.mark.parametrize("port", [0, 65536, -1, True, "80"])
def test_set_port_rejects_bad_values(path, port):
    store = DeviceStore(path)
    with pytest.raises(StoreError):
        store.set_port(port)
    assert store.port is None


def test_add_refuses_a_duplicate_id_and_keeps_the_original_key(path):
    store = DeviceStore(path)
    store.add(device(1))
    with pytest.raises(StoreError):
        store.add(Device(device(1).device_id, bytes(32), "Other", 1))
    assert store.devices() == [device(1)]
    assert DeviceStore(path).devices() == [device(1)]


@pytest.mark.parametrize(
    "bad",
    [
        Device(bytes(15), bytes(32), "x", 1),
        Device(bytes(16), bytes(31), "x", 1),
        Device(bytes(16), bytes(32), "x", -1),
        Device(bytes(16), bytes(32), "x", True),
    ],
)
def test_add_refuses_a_malformed_device(path, bad):
    store = DeviceStore(path)
    with pytest.raises(StoreError):
        store.add(bad)
    assert store.devices() == []


def test_unusual_names_round_trip(path):
    odd = [Device(bytes([n]) * 16, bytes(32), name, 1) for n, name in enumerate(["Zoë 📱", "lone \ud800 surrogate"], 1)]
    store = DeviceStore(path)
    for item in odd:
        store.add(item)
    assert DeviceStore(path).devices() == odd


def test_repr_shows_neither_key_nor_name():
    text = repr(device(1, name="SecretName"))
    assert device(1).key.hex() not in text and "SecretName" not in text and str(device(1).key) not in text


def failing_replace(*_args):
    raise OSError("disk full")


def test_failed_add_keeps_the_old_file_memory_and_leaves_no_temp_file(path, monkeypatch):
    store = DeviceStore(path)
    store.add(device(1))
    before = path.read_bytes()
    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(StoreError):
        store.add(device(2))
    assert store.devices() == [device(1)]
    assert path.read_bytes() == before
    assert os.listdir(path.parent) == ["devices.json"]


def test_failed_fsync_is_a_store_error_without_leftovers(path, monkeypatch):
    store = DeviceStore(path)
    before = path.read_bytes()
    monkeypatch.setattr(os, "fsync", failing_replace)
    with pytest.raises(StoreError):
        store.add(device(1))
    assert store.devices() == []
    assert path.read_bytes() == before
    assert os.listdir(path.parent) == ["devices.json"]


def test_failed_set_port_changes_nothing(path, monkeypatch):
    store = DeviceStore(path)
    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(StoreError):
        store.set_port(5000)
    assert store.port is None


def test_failed_remove_still_drops_the_key_from_memory(path, monkeypatch):
    store = DeviceStore(path)
    store.add(device(1))
    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(StoreError):
        store.remove(device(1).device_id)
    assert store.get(device(1).device_id) is None
    assert DeviceStore(path).devices() == [device(1)]


def test_failed_first_write_is_a_store_error(path, monkeypatch):
    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(StoreError):
        DeviceStore(path)
    assert os.listdir(path.parent) == []


def test_temp_file_is_created_owner_only_before_any_data_is_written(path, monkeypatch):
    store = DeviceStore(path)
    seen = []
    real_replace = os.replace

    def spy(src, dst):
        seen.append(mode(path.parent / os.path.basename(src)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    store.add(device(1))
    assert seen == [0o600]


def test_wide_permissions_are_tightened_on_load(path):
    DeviceStore(path).add(device(1))
    path.chmod(0o666)
    store = DeviceStore(path)
    assert mode(path) == 0o600
    assert store.devices() == [device(1)]


def valid_doc(**changes) -> dict:
    entry = {"deviceId": "11" * 16, "deviceKey": "22" * 32, "name": "P", "createdAt": 5}
    return {**{"pluginId": "aa" * 16, "port": None, "devices": [entry]}, **changes}


CORRUPT = {
    "not json": b"{not json",
    "invalid utf-8": b"\xff\xfe\x00",
    "empty file": b"",
    "array": b"[]",
    "no devices": json.dumps({"pluginId": "aa" * 16, "port": None}).encode(),
    "plugin id upper case": json.dumps(valid_doc(pluginId="AA" * 16)).encode(),
    "plugin id short": json.dumps(valid_doc(pluginId="aa" * 15)).encode(),
    "port zero": json.dumps(valid_doc(port=0)).encode(),
    "port bool": json.dumps(valid_doc(port=True)).encode(),
    "port string": json.dumps(valid_doc(port="80")).encode(),
    "devices not a list": json.dumps(valid_doc(devices=5)).encode(),
    "device not an object": json.dumps(valid_doc(devices=["x"])).encode(),
    "key short": json.dumps(valid_doc(devices=[{"deviceId": "11" * 16, "deviceKey": "22" * 31, "name": "P", "createdAt": 5}])).encode(),
    "key upper case": json.dumps(valid_doc(devices=[{"deviceId": "11" * 16, "deviceKey": "AA" * 32, "name": "P", "createdAt": 5}])).encode(),
    "name not a string": json.dumps(valid_doc(devices=[{"deviceId": "11" * 16, "deviceKey": "22" * 32, "name": 5, "createdAt": 5}])).encode(),
    "created bool": json.dumps(valid_doc(devices=[{"deviceId": "11" * 16, "deviceKey": "22" * 32, "name": "P", "createdAt": True}])).encode(),
    "duplicate device": json.dumps(valid_doc(devices=[valid_doc()["devices"][0]] * 2)).encode(),
    "missing field": json.dumps(valid_doc(devices=[{"deviceId": "11" * 16}])).encode(),
}


def test_a_valid_document_loads(path):
    path.parent.mkdir()
    path.write_text(json.dumps(valid_doc(port=1234)))
    store = DeviceStore(path)
    assert store.recovered_from_corruption is False
    assert store.port == 1234 and store.plugin_id == bytes([0xAA]) * 16
    assert store.devices() == [Device(bytes([0x11]) * 16, bytes([0x22]) * 32, "P", 5)]


@pytest.mark.parametrize("content", CORRUPT.values(), ids=CORRUPT.keys())
def test_corrupt_file_is_moved_aside_and_a_fresh_store_started(path, content):
    path.parent.mkdir()
    path.write_bytes(content)
    path.chmod(0o644)
    store = DeviceStore(path)
    assert store.recovered_from_corruption is True
    assert store.devices() == [] and store.port is None
    aside = path.with_name("devices.json.corrupt")
    assert aside.read_bytes() == content
    assert mode(aside) == 0o600
    assert mode(path) == 0o600
    assert DeviceStore(path).recovered_from_corruption is False


def test_a_second_corrupt_file_does_not_overwrite_the_first(path):
    path.parent.mkdir()
    path.write_bytes(b"first")
    DeviceStore(path)
    path.write_bytes(b"second")
    DeviceStore(path)
    assert path.with_name("devices.json.corrupt").read_bytes() == b"first"
    assert path.with_name("devices.json.corrupt.1").read_bytes() == b"second"


def test_an_unreadable_path_is_a_store_error_not_a_reset(tmp_path):
    folder = tmp_path / "devices.json"
    folder.mkdir()
    with pytest.raises(StoreError):
        DeviceStore(folder)
    assert folder.is_dir()
