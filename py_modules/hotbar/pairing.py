# Runs one pairing session: builds the QR link and answers the pair and confirm requests.
import hashlib
import hmac
import ipaddress
import os
import time
from collections.abc import Callable, Container
from dataclasses import dataclass, field
from urllib.parse import quote

from hotbar import constants as c
from hotbar import crypto
from hotbar.messages import CONTROL_CHARS, PLAIN_HTTP_STATUS, BodyError, parse_hex, parse_object, truncate_utf8
from hotbar.store import Device, StoreError

_QR_SCHEME = "hotbar"
_PAIR_FIELDS = {"token", "phonePublic", "phoneNonce", "name"}
_CONFIRM_FIELDS = {"deviceId", "confirm"}


def build_qr_uri(
    *,
    host: str,
    port: int,
    token: bytes,
    secret: bytes,
    fingerprint: bytes,
    plugin_id: bytes,
    hostname: str,
) -> str:
    if str(ipaddress.IPv4Address(host)) != host or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("host must be dotted IPv4 and port 1 to 65535")
    name = truncate_utf8(hostname, c.HOSTNAME_MAX_BYTES).encode("utf-8")
    if not name:
        raise ValueError("hostname is empty")
    return (
        f"{_QR_SCHEME}://pair?v={c.VERSION}&host={host}&port={port}&token={token.hex()}"
        f"&secret={secret.hex()}&fp={fingerprint.hex()}&pid={plugin_id.hex()}&name={quote(name, safe='')}"
    )


def _plain(code: str) -> tuple[int, dict]:
    return PLAIN_HTTP_STATUS[code], {"error": code}


def _parse_body(body: bytes, fields: set[str]) -> dict | None:
    if len(body) > c.PAIR_BODY_MAX:
        return None
    try:
        obj = parse_object(body)
    except BodyError:
        return None
    return obj if obj.keys() == fields else None


def _valid_name(name: object) -> bool:
    if not isinstance(name, str):
        return False
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return 1 <= size <= c.NAME_MAX_BYTES and CONTROL_CHARS.search(name) is None


def _parse_pair(body: bytes) -> tuple[bytes, bytes, bytes, str] | None:
    obj = _parse_body(body, _PAIR_FIELDS)
    if obj is None:
        return None
    token = parse_hex(obj["token"], c.TOKEN_LEN)
    public = parse_hex(obj["phonePublic"], 32)
    nonce = parse_hex(obj["phoneNonce"], c.PAIR_NONCE_LEN)
    if token is None or public is None or nonce is None or not _valid_name(obj["name"]):
        return None
    return token, public, nonce, obj["name"]


def _parse_confirm(body: bytes) -> tuple[bytes, bytes] | None:
    obj = _parse_body(body, _CONFIRM_FIELDS)
    if obj is None:
        return None
    device_id = parse_hex(obj["deviceId"], c.DEVICE_ID_LEN)
    confirm = parse_hex(obj["confirm"], c.CONFIRM_LEN)
    return None if device_id is None or confirm is None else (device_id, confirm)


def reject_without_session(body: bytes) -> tuple[int, dict]:
    """Answer to POST pair when no session exists: the body is judged first."""
    return _plain("bad_message" if _parse_pair(body) is None else "pair_expired")


def reject_confirm_without_session(body: bytes) -> tuple[int, dict]:
    """Same for POST pair/confirm."""
    return _plain("bad_message" if _parse_confirm(body) is None else "pair_expired")


@dataclass
class _Pending:
    device_id: bytes
    name: str = field(repr=False)
    device_key: bytes = field(repr=False)
    confirm_phone: bytes = field(repr=False)
    confirm_plugin: bytes = field(repr=False)


class PairingSession:
    """One QR, one phone. Draws from `random` in this order: private key, token, secret,
    then at pair time the plugin nonce and the device id (again while the id is taken)."""

    def __init__(
        self,
        *,
        plugin_id: bytes,
        host: str,
        port: int,
        hostname: str,
        now_s: float,
        random: Callable[[int], bytes] = os.urandom,
        wall_clock: Callable[[], float] = time.time,
    ):
        self._random = random
        self._wall_clock = wall_clock
        self._private: bytes | None = random(32)
        self._public = crypto.x25519_public(self._private)
        self._token: bytes | None = random(c.TOKEN_LEN)
        self._secret: bytes | None = random(c.SECRET_LEN)
        self._deadline_s = now_s + c.QR_TTL_S
        self._token_used = False
        self._failures = 0
        self._pending: _Pending | None = None
        self._ended = False
        self.succeeded = False
        # Holds the token and secret, so it is blanked when the session ends.
        self.uri = build_qr_uri(
            host=host,
            port=port,
            token=self._token,
            secret=self._secret,
            fingerprint=hashlib.sha256(self._public).digest()[: c.FINGERPRINT_LEN],
            plugin_id=plugin_id,
            hostname=hostname,
        )

    def is_active(self, now_s: float) -> bool:
        self._expire(now_s)
        return not self._ended

    def expires_in_s(self, now_s: float) -> float:
        """Time left on the QR deadline, or on the confirm deadline once a pair request succeeded."""
        self._expire(now_s)
        return 0.0 if self._ended else self._deadline_s - now_s

    def end(self) -> None:
        self._ended = True
        self._private = self._token = self._secret = self._pending = None
        self.uri = ""

    def pair(self, body: bytes, now_s: float, taken_ids: Container[bytes]) -> tuple[int, dict]:
        self._expire(now_s)
        request = _parse_pair(body)
        if request is None:
            return self._fail("bad_message")
        token, phone_public, phone_nonce, name = request
        if self._ended or self._token_used:
            return _plain("pair_expired")
        if not hmac.compare_digest(token, self._token):
            return self._fail("token_invalid")
        # The token is spent from here on, whatever happens next.
        self._token_used = True
        plugin_nonce = self._random(c.PAIR_NONCE_LEN)
        device_id = self._random(c.DEVICE_ID_LEN)
        while device_id in taken_ids:
            device_id = self._random(c.DEVICE_ID_LEN)
        try:
            shared = crypto.x25519_shared(self._private, phone_public)
        except crypto.LowOrderPointError:
            self.end()
            return _plain("bad_message")
        salt = self._secret + phone_nonce + plugin_nonce
        suffix = phone_public + self._public + device_id

        def derive(label: bytes) -> bytes:
            return crypto.hkdf(shared, salt, label + suffix, 32)

        self._pending = _Pending(
            device_id,
            name,
            derive(c.LABEL_DEVICE_KEY),
            derive(c.LABEL_CONFIRM_PHONE),
            derive(c.LABEL_CONFIRM_PLUGIN),
        )
        self._deadline_s = now_s + c.PAIR_CONFIRM_TTL_S
        return 200, {
            "pluginPublic": self._public.hex(),
            "pluginNonce": plugin_nonce.hex(),
            "deviceId": device_id.hex(),
        }

    def confirm(
        self, body: bytes, now_s: float, commit: Callable[[Device], None]
    ) -> tuple[int, dict]:
        self._expire(now_s)
        request = _parse_confirm(body)
        if request is None:
            return _plain("bad_message")
        device_id, confirm = request
        pending = self._pending
        if self._ended or pending is None or not hmac.compare_digest(device_id, pending.device_id):
            return _plain("pair_expired")
        if not hmac.compare_digest(confirm, pending.confirm_phone):
            self.end()
            return _plain("confirm_failed")
        device = Device(pending.device_id, pending.device_key, pending.name, int(self._wall_clock()))
        try:
            commit(device)
        except StoreError:
            self.end()
            return _plain("internal")
        answer = {"confirm": pending.confirm_plugin.hex()}
        self.succeeded = True
        self.end()
        return 200, answer

    def _expire(self, now_s: float) -> None:
        if not self._ended and now_s >= self._deadline_s:
            self.end()

    def _fail(self, code: str) -> tuple[int, dict]:
        if not self._ended:
            self._failures += 1
            if self._failures >= c.PAIR_MAX_FAILURES:
                self.end()
        return _plain(code)
