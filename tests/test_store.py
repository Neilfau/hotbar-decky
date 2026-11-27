# Tests for the device key file: permissions, durability, failure handling and recovery.
import json
import os
import stat

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


def test_a_symlinked_file_is_not_loaded_and_its_target_is_untouched(path, tmp_path):
    path.parent.mkdir()
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps(valid_doc(port=1234)))
    target.chmod(0o666)
    before = target.read_bytes()
    path.symlink_to(target)
    with pytest.raises(StoreError):
        DeviceStore(path)
    assert target.read_bytes() == before
    assert mode(target) == 0o666
    assert path.is_symlink()


@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_a_non_regular_file_is_refused_like_a_symlink(path, kind):
    path.parent.mkdir()
    if kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises(StoreError):
        DeviceStore(path)
    assert not path.is_symlink() and not path.is_file()


def test_a_failed_remove_leaves_a_write_pending_until_a_retry_succeeds(path, monkeypatch):
    store = DeviceStore(path)
    store.add(device(1))
    assert store.write_pending is False
    with monkeypatch.context() as m:
        m.setattr(os, "replace", failing_replace)
        with pytest.raises(StoreError):
            store.remove(device(1).device_id)
        assert store.write_pending is True
        assert DeviceStore(path).devices() == [device(1)]
        assert store.retry_write() is False  # still failing, and it does not raise
        assert store.write_pending is True
    assert store.retry_write() is True
    assert store.write_pending is False
    assert DeviceStore(path).devices() == []


def test_a_later_successful_write_clears_the_pending_flag(path, monkeypatch):
    store = DeviceStore(path)
    store.add(device(1))
    with monkeypatch.context() as m:
        m.setattr(os, "replace", failing_replace)
        with pytest.raises(StoreError):
            store.remove_all()
    assert store.write_pending is True
    store.set_port(5000)
    assert store.write_pending is False
    assert store.retry_write() is True


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


# the state directory

def test_the_state_directory_is_created_owner_only(path):
    DeviceStore(path)
    assert mode(path.parent) == 0o700


def test_a_directory_with_a_wider_mode_is_set_back_to_owner_only(path):
    path.parent.mkdir()
    path.parent.chmod(0o755)
    store = DeviceStore(path)
    assert mode(path.parent) == 0o700
    assert DeviceStore(path).plugin_id == store.plugin_id


def test_a_directory_with_a_special_mode_bit_is_set_back_to_owner_only(path):
    path.parent.mkdir()
    path.parent.chmod(0o1700)
    DeviceStore(path)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_a_directory_owned_by_someone_else_is_refused_and_left_alone(path, monkeypatch):
    path.parent.mkdir()
    path.parent.chmod(0o755)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(StoreError):
        DeviceStore(path)
    assert mode(path.parent) == 0o755
    assert os.listdir(path.parent) == []


def test_a_symlinked_directory_is_refused_and_its_target_is_untouched(path, tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    target.chmod(0o755)
    path.parent.symlink_to(target)
    with pytest.raises(StoreError):
        DeviceStore(path)
    assert mode(target) == 0o755
    assert os.listdir(target) == []


def test_a_directory_that_is_a_file_is_refused(path):
    path.parent.write_text("x")
    with pytest.raises(StoreError):
        DeviceStore(path)


# moving a file out of the desktop user's settings directory

@pytest.fixture
def legacy(tmp_path):
    folder = tmp_path / "decky-settings"
    folder.mkdir()
    return folder / "devices.json"


def write_legacy(legacy, content: bytes, perm: int = 0o644):
    legacy.write_bytes(content)
    legacy.chmod(perm)


def test_a_legacy_file_is_moved_with_its_plugin_id_and_keys(path, legacy):
    write_legacy(legacy, json.dumps(valid_doc(port=1234)).encode())
    store = DeviceStore(path, legacy_path=legacy)
    assert store.recovered_from_corruption is False
    assert store.plugin_id == bytes([0xAA]) * 16 and store.port == 1234
    assert store.devices() == [Device(bytes([0x11]) * 16, bytes([0x22]) * 32, "P", 5)]
    assert not os.path.lexists(legacy)
    assert mode(path) == 0o600
    reloaded = DeviceStore(path, legacy_path=legacy)
    assert (reloaded.plugin_id, reloaded.port, reloaded.devices()) == (store.plugin_id, 1234, store.devices())
    assert os.listdir(path.parent) == ["devices.json"]


def test_a_crash_between_the_write_and_the_unlink_leaves_both_files_and_the_new_one_wins(path, legacy, monkeypatch):
    write_legacy(legacy, json.dumps(valid_doc()).encode())
    with monkeypatch.context() as m:
        m.setattr(os, "unlink", failing_replace)  # the legacy file cannot be removed
        first = DeviceStore(path, legacy_path=legacy)
    assert first.plugin_id == bytes([0xAA]) * 16
    assert legacy.exists() and path.exists()
    # The new file is changed after the copy, so the legacy one is stale.
    first.add(device(1))
    write_legacy(legacy, json.dumps(valid_doc(pluginId="bb" * 16)).encode())
    second = DeviceStore(path, legacy_path=legacy)
    assert second.plugin_id == bytes([0xAA]) * 16
    assert device(1) in second.devices()
    assert not os.path.lexists(legacy)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_an_unreadable_legacy_file_is_a_store_error_and_stays_in_place(path, legacy, tmp_path, kind):
    if kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text(json.dumps(valid_doc()))
        legacy.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(legacy)
    else:
        legacy.mkdir()
    with pytest.raises(StoreError):
        DeviceStore(path, legacy_path=legacy)
    assert os.path.lexists(legacy)
    assert not os.path.lexists(path)
    assert os.listdir(path.parent) == []


def test_a_failed_write_during_the_move_keeps_the_legacy_file(path, legacy, monkeypatch):
    content = json.dumps(valid_doc()).encode()
    write_legacy(legacy, content)
    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(StoreError):
        DeviceStore(path, legacy_path=legacy)
    assert legacy.read_bytes() == content
    assert os.listdir(path.parent) == []


@pytest.mark.parametrize("content", [b"{not json", b"", json.dumps(valid_doc(port=0)).encode()])
def test_a_corrupt_legacy_file_is_copied_into_the_state_directory_and_removed(path, legacy, content):
    write_legacy(legacy, content)
    store = DeviceStore(path, legacy_path=legacy)
    assert store.recovered_from_corruption is True
    assert store.devices() == [] and store.port is None
    aside = path.with_name("devices.json.corrupt")
    assert aside.read_bytes() == content and mode(aside) == 0o600
    assert not os.path.lexists(legacy)
    assert sorted(os.listdir(path.parent)) == ["devices.json", "devices.json.corrupt"]
    assert DeviceStore(path, legacy_path=legacy).recovered_from_corruption is False


@pytest.mark.parametrize("content", [json.dumps(valid_doc()).encode(), b"{not json"], ids=["valid", "corrupt"])
def test_a_legacy_file_is_copied_not_renamed(path, legacy, content):
    write_legacy(legacy, content)
    link = legacy.with_name("held-open")
    os.link(legacy, link)  # stands in for a descriptor or a link the desktop user kept
    DeviceStore(path, legacy_path=legacy)
    assert not os.path.lexists(legacy)
    assert link.read_bytes() == content
    for moved in (path, path.with_name("devices.json.corrupt")):
        if moved.exists():
            assert not os.path.samefile(moved, link)


def test_legacy_corrupt_files_are_copied_into_the_state_directory_and_removed(path, legacy):
    path.parent.mkdir()
    write_legacy(path.with_name("devices.json.corrupt"), b"already here", 0o600)
    write_legacy(legacy.with_name("devices.json.corrupt"), b"old one")
    write_legacy(legacy.with_name("devices.json.corrupt.1"), b"old two")
    (legacy.parent / "other.json").write_bytes(b"not ours")
    DeviceStore(path, legacy_path=legacy)
    kept = {name: (path.parent / name).read_bytes() for name in os.listdir(path.parent) if "corrupt" in name}
    assert sorted(kept.values()) == [b"already here", b"old one", b"old two"]
    assert all(mode(path.parent / name) == 0o600 for name in kept)
    assert os.listdir(legacy.parent) == ["other.json"]


def test_legacy_corrupt_files_move_even_when_the_new_file_already_exists(path, legacy):
    DeviceStore(path)
    write_legacy(legacy.with_name("devices.json.corrupt.3"), b"late")
    DeviceStore(path, legacy_path=legacy)
    assert path.with_name("devices.json.corrupt").read_bytes() == b"late"
    assert os.listdir(legacy.parent) == []


def test_an_unreadable_legacy_corrupt_file_does_not_stop_the_start(path, legacy, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    legacy.with_name("devices.json.corrupt").symlink_to(target)
    store = DeviceStore(path, legacy_path=legacy)
    assert store.devices() == []
    assert legacy.with_name("devices.json.corrupt").is_symlink() and target.read_bytes() == b"secret"


@pytest.mark.parametrize("folder", ["missing", "a file"])
def test_without_a_legacy_file_a_fresh_store_starts(path, tmp_path, folder):
    settings = tmp_path / "decky-settings-2"
    if folder == "a file":
        settings.write_text("x")
    store = DeviceStore(path, legacy_path=settings / "devices.json")
    assert store.recovered_from_corruption is False and store.devices() == []
    assert os.listdir(path.parent) == ["devices.json"]


@pytest.mark.parametrize("how", ["same path", "symlinked folder"])
def test_a_legacy_folder_that_is_the_state_folder_leaves_the_live_file_alone(path, tmp_path, how):
    first = DeviceStore(path)
    first.add(device(1))
    if how == "same path":
        legacy_path = path
    else:
        (tmp_path / "link").symlink_to(path.parent)
        legacy_path = tmp_path / "link" / "devices.json"
    store = DeviceStore(path, legacy_path=legacy_path)
    assert path.exists() and store.devices() == [device(1)]
    assert DeviceStore(path).plugin_id == first.plugin_id
