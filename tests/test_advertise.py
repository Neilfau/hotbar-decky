# Checks the avahi service file: its content, the atomic write, removal and the unwritable-folder path.
import logging
import os
import stat

from hotbar import advertise

PLUGIN_ID = bytes(range(16))
LOGGER = logging.getLogger("advertise-test")


def test_service_file_names_type_port_and_txt_records():
    text = advertise.service_file_text(47126, PLUGIN_ID)
    assert "<type>_hotbar._tcp</type>" in text
    assert "<port>47126</port>" in text
    assert "<txt-record>pid=000102030405060708090a0b0c0d0e0f</txt-record>" in text
    assert "<txt-record>v=1</txt-record>" in text


def test_publish_writes_the_file_readable_by_others_and_leaves_no_temp_file(tmp_path):
    assert advertise.publish(tmp_path, 4000, PLUGIN_ID, LOGGER) is True
    assert [p.name for p in tmp_path.iterdir()] == ["hotbar.service"]
    assert (tmp_path / "hotbar.service").read_text() == advertise.service_file_text(4000, PLUGIN_ID)
    assert stat.S_IMODE((tmp_path / "hotbar.service").stat().st_mode) == 0o644


def test_publish_replaces_an_earlier_file(tmp_path):
    advertise.publish(tmp_path, 4000, PLUGIN_ID, LOGGER)
    advertise.publish(tmp_path, 4001, PLUGIN_ID, LOGGER)
    assert "<port>4001</port>" in (tmp_path / "hotbar.service").read_text()
    assert len(list(tmp_path.iterdir())) == 1


def test_a_failed_rename_keeps_the_old_file_and_removes_the_temp_file(tmp_path, monkeypatch):
    advertise.publish(tmp_path, 4000, PLUGIN_ID, LOGGER)

    def failing_replace(*_args):
        raise PermissionError("denied")

    monkeypatch.setattr(os, "replace", failing_replace)
    assert advertise.publish(tmp_path, 4001, PLUGIN_ID, LOGGER) is False
    assert [p.name for p in tmp_path.iterdir()] == ["hotbar.service"]
    assert "<port>4000</port>" in (tmp_path / "hotbar.service").read_text()


def test_missing_folder_logs_one_warning_with_the_error_type_only(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="advertise-test"):
        assert advertise.publish(tmp_path / "absent", 4000, PLUGIN_ID, LOGGER) is False
    assert [r.getMessage() for r in caplog.records] == ["could not publish the service file: FileNotFoundError"]
    assert not (tmp_path / "absent").exists()


def test_withdraw_removes_the_file_and_is_harmless_twice_or_without_a_folder(tmp_path):
    advertise.publish(tmp_path, 4000, PLUGIN_ID, LOGGER)
    advertise.withdraw(tmp_path, LOGGER)
    assert list(tmp_path.iterdir()) == []
    advertise.withdraw(tmp_path, LOGGER)
    advertise.withdraw(tmp_path / "absent", LOGGER)


def test_withdraw_failure_is_logged_not_raised(tmp_path, caplog):
    (tmp_path / "hotbar.service").mkdir()  # unlink on a directory fails
    with caplog.at_level(logging.INFO, logger="advertise-test"):
        advertise.withdraw(tmp_path, LOGGER)
    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 1 and messages[0].startswith("could not remove the service file: ")


def test_only_the_final_name_ends_in_service(tmp_path, monkeypatch):
    seen = []
    real_replace = os.replace

    def spying_replace(src, dst):
        seen.append(os.path.basename(src))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spying_replace)
    advertise.publish(tmp_path, 4000, PLUGIN_ID, LOGGER)
    assert seen and not seen[0].endswith(".service")
    assert (tmp_path / "hotbar.service").exists()
