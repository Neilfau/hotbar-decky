# Checks that the self-check logs one plain line per check, never raises and never logs payload data.
import logging

from hotbar import selfcheck

LOGGER = logging.getLogger("selfcheck-test")


def test_every_check_logs_one_line_with_names_booleans_and_milliseconds(tmp_path, caplog):
    uinput = tmp_path / "uinput"
    uinput.write_bytes(b"")
    with caplog.at_level(logging.INFO, logger="selfcheck-test"):
        lines = selfcheck.run(LOGGER, uinput_path=uinput, services_dir=tmp_path)
    assert [r.getMessage() for r in caplog.records] == lines
    by_name = {line.split(":")[0].removeprefix("selfcheck "): line.split(": ", 1)[1] for line in lines}
    assert list(by_name) == [
        "python", "hashlib_sha256", "hmac", "secrets", "fcntl", "ctypes", "aiohttp",
        "x25519_shared", "chacha20poly1305_seal_512", "effective_uid",
        "uinput_writable", "avahi_services_dir_writable",
    ]
    for name in ("hashlib_sha256", "hmac", "secrets", "fcntl", "ctypes", "aiohttp"):
        assert by_name[name] == "ok"
    for name in ("x25519_shared", "chacha20poly1305_seal_512"):
        assert by_name[name].endswith(" ms") and by_name[name][:-3].isdigit()
    assert by_name["effective_uid"].isdigit()
    assert by_name["uinput_writable"] == "true"
    assert by_name["avahi_services_dir_writable"] == "true"


def test_absent_paths_report_false(tmp_path):
    lines = selfcheck.run(LOGGER, uinput_path=tmp_path / "none", services_dir=tmp_path / "none")
    assert "selfcheck uinput_writable: false" in lines
    assert "selfcheck avahi_services_dir_writable: false" in lines


def test_a_failing_check_is_reported_by_error_type_without_raising(tmp_path, monkeypatch):
    def broken(*_args):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(selfcheck.crypto, "x25519_shared", broken)
    monkeypatch.setattr(selfcheck.crypto, "aead_seal", broken)
    lines = selfcheck.run(LOGGER, uinput_path=tmp_path, services_dir=tmp_path)
    assert "selfcheck x25519_shared: failed (RuntimeError)" in lines
    assert "selfcheck chacha20poly1305_seal_512: failed (RuntimeError)" in lines
    assert not any("secret detail" in line for line in lines)


def test_a_failing_logger_does_not_stop_the_run(tmp_path):
    class BrokenLogger:
        def info(self, _message):
            raise OSError("disk full")

    lines = selfcheck.run(BrokenLogger(), uinput_path=tmp_path, services_dir=tmp_path)  # type: ignore[arg-type]
    assert len(lines) == 12
