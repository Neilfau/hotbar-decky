# Test support: a minimal phone side that pairs, seals requests and opens the plugin's answers.
import hashlib
import hmac
import ipaddress
import json
import os
import re
from dataclasses import dataclass

from hotbar import constants as c
from hotbar import crypto
from hotbar.envelope import Header, open_envelope, seal

# Wire error code to the phone's transport error name; None means the call completes as delivered.
TRANSPORT_ERROR = {
    "bad_message": "failed",
    "version_too_new": "versionMismatch",
    "bad_direction": "failed",
    "unknown_device": "unauthorized",
    "auth_failed": "unauthorized",
    "pair_expired": "unauthorized",
    "token_invalid": "unauthorized",
    "confirm_failed": "unauthorized",
    "rate_limited": "rateLimited",
    "internal": "failed",
    "challenge_required": "failed",
    "challenge_invalid": "failed",
    "replayed": None,
    "counter_too_old": "failed",
    "bad_body": "failed",
    "unknown_type": "unsupported",
    "unsupported_key": "unsupported",
    "unsupported_char": "unsupported",
}


class PairingFailure(Exception):
    """The phone stops pairing and keeps nothing."""


def hex_bytes(value: object, n_bytes: int) -> bytes | None:
    if isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{2 * n_bytes}}}", value):
        return bytes.fromhex(value)
    return None


def encode(body: dict) -> bytes:
    return json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()


@dataclass(frozen=True)
class PairingUri:
    host: str
    port: int
    token: bytes
    secret: bytes
    fingerprint: bytes
    plugin_id: bytes
    name: str


_PARAMS = ["v", "host", "port", "token", "secret", "fp", "pid", "name"]
_NAME = re.compile(r"(?:[A-Za-z0-9\-._~]|%[0-9A-Fa-f]{2})+")


def parse_uri(uri: str) -> PairingUri:
    prefix = "hotbar://pair?"
    if not uri.startswith(prefix):
        raise PairingFailure("not a pairing link")
    pairs = [part.partition("=") for part in uri[len(prefix) :].split("&")]
    if [k for k, _, _ in pairs] != _PARAMS or not all(sep for _, sep, _ in pairs):
        raise PairingFailure("parameters")
    v = {k: val for k, _, val in pairs}
    port = int(v["port"]) if re.fullmatch("[0-9]{1,5}", v["port"]) else 0
    token, secret, fp, pid = (hex_bytes(v[k], n) for k, n in (("token", 16), ("secret", 32), ("fp", 16), ("pid", 16)))
    name = _percent_decode(v["name"])
    if v["v"] != "1" or not _dotted_ipv4(v["host"]) or not 1 <= port <= 65535:
        raise PairingFailure("version, host or port")
    if None in (token, secret, fp, pid) or name is None or not 1 <= len(name.encode()) <= c.HOSTNAME_MAX_BYTES:
        raise PairingFailure("value")
    return PairingUri(v["host"], port, token, secret, fp, pid, name)


def _dotted_ipv4(text: str) -> bool:
    try:
        return str(ipaddress.IPv4Address(text)) == text
    except ValueError:
        return False


def _percent_decode(text: str) -> str | None:
    if not _NAME.fullmatch(text):
        return None
    out = bytearray()
    parts = re.split(r"(%[0-9A-Fa-f]{2})", text)
    for i, part in enumerate(parts):
        out += bytes.fromhex(part[1:]) if i % 2 else part.encode()
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


class PhonePairing:
    def __init__(self, uri: str, name: str, private: bytes, nonce: bytes):
        self.uri = parse_uri(uri)
        self.name = name
        self.nonce = nonce
        self.public = crypto.x25519_public(private)
        self._private = private
        self.device_id: bytes | None = None
        self.device_key: bytes | None = None
        self._confirm_plugin: bytes | None = None

    def pair_request(self) -> dict:
        return {
            "token": self.uri.token.hex(),
            "phonePublic": self.public.hex(),
            "phoneNonce": self.nonce.hex(),
            "name": self.name,
        }

    def on_pair_response(self, response: dict) -> dict:
        """Checks the fingerprint first, then derives the keys and returns the confirm request."""
        if set(response) != {"pluginPublic", "pluginNonce", "deviceId"}:
            raise PairingFailure("response fields")
        plugin_public = hex_bytes(response["pluginPublic"], 32)
        plugin_nonce = hex_bytes(response["pluginNonce"], c.PAIR_NONCE_LEN)
        device_id = hex_bytes(response["deviceId"], c.DEVICE_ID_LEN)
        if plugin_public is None or plugin_nonce is None or device_id is None:
            raise PairingFailure("response values")
        if not hmac.compare_digest(hashlib.sha256(plugin_public).digest()[: c.FINGERPRINT_LEN], self.uri.fingerprint):
            raise PairingFailure("fingerprint")
        try:
            shared = crypto.x25519_shared(self._private, plugin_public)
        except crypto.LowOrderPointError:
            raise PairingFailure("low order point") from None
        salt = self.uri.secret + self.nonce + plugin_nonce
        suffix = self.public + plugin_public + device_id

        def derive(label: bytes) -> bytes:
            return crypto.hkdf(shared, salt, label + suffix, 32)

        self.device_id = device_id
        self.device_key = derive(c.LABEL_DEVICE_KEY)
        self._confirm_plugin = derive(c.LABEL_CONFIRM_PLUGIN)
        return {"deviceId": device_id.hex(), "confirm": derive(c.LABEL_CONFIRM_PHONE).hex()}

    def verify_confirm(self, response: dict) -> None:
        got = hex_bytes(response.get("confirm"), c.CONFIRM_LEN) if set(response) == {"confirm"} else None
        if got is None or not hmac.compare_digest(got, self._confirm_plugin):
            self.device_id = self.device_key = None
            raise PairingFailure("plugin confirmation")


class Sender:
    """One sender: a sender id and a counter that starts at 0 and rises with each message."""

    def __init__(self, device_id: bytes, device_key: bytes, sender_id: bytes | None = None, random=os.urandom):
        self.device_id = device_id
        self.device_key = device_key
        self.sender_id = random(c.SENDER_ID_LEN) if sender_id is None else sender_id
        self.counter = 0
        self._random = random

    def seal(self, body: dict) -> bytes:
        header = Header(
            c.VERSION, c.DIR_PHONE_TO_PLUGIN, self.device_id, self.sender_id, self.counter, self._random(c.SALT_LEN)
        )
        self.counter += 1
        return seal(self.device_key, header, encode(body))


@dataclass(frozen=True)
class Received:
    accepted: bool
    reason: str | None
    response: dict | None


def _strict_response(body: bytes) -> dict | None:
    try:
        obj = json.loads(body.decode("utf-8"))
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    kind = obj.get("type")
    extra = {"ok": set(), "welcome": {"pluginId", "maxVersion", "hostname"}, "error": {"error"}}
    extra = extra.get(kind) if isinstance(kind, str) else None
    if extra is None:
        return None
    limited = obj.get("error") == "rate_limited"
    if limited:
        extra = extra | {"retryAfterMs"}
    if obj.keys() != {"type", "sender", "counter"} | extra:
        return None
    counter = obj["counter"]
    good = hex_bytes(obj["sender"], c.SENDER_ID_LEN) is not None and type(counter) is int and counter >= 0
    if obj["type"] == "welcome":
        host, version = obj["hostname"], obj["maxVersion"]
        good = good and hex_bytes(obj["pluginId"], c.PLUGIN_ID_LEN) is not None and type(version) is int
        good = good and isinstance(host, str) and len(host.encode("utf-8", "replace")) <= c.HOSTNAME_MAX_BYTES
    if obj["type"] == "error":
        good = good and isinstance(obj["error"], str) and obj["error"] in TRANSPORT_ERROR
        retry = obj.get("retryAfterMs")
        good = good and (not limited or (type(retry) is int and retry >= 1))
    return obj if good else None


def phone_receive(
    wire: bytes, device_id: bytes, device_key: bytes, outstanding: set[tuple[bytes, int]]
) -> Received:
    """The phone's receive steps; an accepted answer is removed from `outstanding`."""

    def drop(reason: str) -> Received:
        return Received(False, reason, None)

    if not c.MIN_ENVELOPE_LEN <= len(wire) <= c.MAX_ENVELOPE_LEN:
        return drop("length")
    if wire[0] != c.VERSION:
        return drop("version")
    if wire[1] != c.DIR_PLUGIN_TO_PHONE:
        return drop("direction")
    if wire[2:18] != device_id:
        return drop("device")
    try:
        _, body = open_envelope(device_key, wire)
    except crypto.AuthenticationError:
        return drop("auth")
    response = _strict_response(body)
    if response is None:
        return drop("body")
    request = (bytes.fromhex(response["sender"]), response["counter"])
    if request not in outstanding:
        return drop("not_outstanding")
    outstanding.discard(request)
    return Received(True, None, response)
