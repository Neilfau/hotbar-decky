# Lets the app find this machine again when its address changes, by publishing an avahi service file for the listening port.
import contextlib
import logging
import os
import tempfile
from pathlib import Path

DEFAULT_SERVICES_DIR = Path("/etc/avahi/services")
SERVICE_FILE_NAME = "hotbar.service"
SERVICE_TYPE = "_hotbar._tcp"
TXT_VERSION = "1"

_TEMPLATE = """<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">%h</name>
  <service>
    <type>{type}</type>
    <port>{port}</port>
    <txt-record>pid={pid}</txt-record>
    <txt-record>v={version}</txt-record>
  </service>
</service-group>
"""


def service_file_text(port: int, plugin_id: bytes) -> str:
    return _TEMPLATE.format(type=SERVICE_TYPE, port=port, pid=plugin_id.hex(), version=TXT_VERSION)


def publish(services_dir: Path, port: int, plugin_id: bytes, logger: logging.Logger) -> bool:
    """Writes the service file for `port`, replacing any earlier one. Never raises: if the folder is
    missing or not writable the app still finds the machine by its last address and its .local name.
    A file left behind by a crash names a dead port until the next start, which costs the app one failed probe."""
    text = service_file_text(port, plugin_id)
    tmp_name = None
    try:
        # The temporary name does not end in .service, so avahi ignores it until the rename.
        fd, tmp_name = tempfile.mkstemp(dir=services_dir, prefix=".hotbar-", suffix=".tmp")
        with os.fdopen(fd, "w") as tmp:
            tmp.write(text)
            os.fchmod(tmp.fileno(), 0o644)  # the avahi daemon runs as its own user and must read it
        os.replace(tmp_name, Path(services_dir) / SERVICE_FILE_NAME)
    except OSError as exc:
        if tmp_name is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
        logger.warning(f"could not publish the service file: {type(exc).__name__}")
        return False
    logger.info("service file written")
    return True


def withdraw(services_dir: Path, logger: logging.Logger) -> None:
    """Removes the service file if there is one. Never raises."""
    try:
        (Path(services_dir) / SERVICE_FILE_NAME).unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning(f"could not remove the service file: {type(exc).__name__}")
        return
    logger.info("service file removed")
