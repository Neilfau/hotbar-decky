# Parses and validates phone message bodies and builds the plugin's reply bodies.
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar

from hotbar import constants as c

# HTTP status of each plaintext error code (path, method and size faults use 404, 405 and 413 instead).
PLAIN_HTTP_STATUS = {
    "bad_message": 400,
    "version_too_new": 426,
    "bad_direction": 400,
    "unknown_device": 401,
    "auth_failed": 401,
    "pair_expired": 410,
    "token_invalid": 401,
    "confirm_failed": 401,
    "rate_limited": 429,
    "internal": 500,
}

CONTROL_CHARS = re.compile("[\x00-\x1f\x7f-\x9f]")
_NOT_IN_TEXT = re.compile("[\x00-\x1f\x7f-\x9f\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}]")


class BodyError(Exception):
    """A body the plugin refuses; `code` is the wire error code and nothing else is kept."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Hello:
    type_name: ClassVar[str] = "hello"


@dataclass(frozen=True)
class Press:
    type_name: ClassVar[str] = "press"
    key: int = field(repr=False)
    mods: int = field(repr=False)


@dataclass(frozen=True)
class TypeText:
    type_name: ClassVar[str] = "type"
    text: str = field(repr=False)
    open: tuple[int, int] | None = field(repr=False)
    submit: bool = field(repr=False)


@dataclass(frozen=True)
class Move:
    type_name: ClassVar[str] = "move"
    dx: int = field(repr=False)
    dy: int = field(repr=False)


@dataclass(frozen=True)
class Button:
    type_name: ClassVar[str] = "button"
    button: str = field(repr=False)
    down: bool = field(repr=False)


@dataclass(frozen=True)
class Scroll:
    type_name: ClassVar[str] = "scroll"
    dx: int = field(repr=False)
    dy: int = field(repr=False)


@dataclass(frozen=True)
class Unpair:
    type_name: ClassVar[str] = "unpair"


Message = Hello | Press | TypeText | Move | Button | Scroll | Unpair


def _reject_constant(_name: str):
    raise ValueError("non-finite number")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def parse_object(body: bytes) -> dict:
    """Strict UTF-8 JSON object; anything else is bad_body."""
    try:
        obj = json.loads(
            bytes(body).decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicates,
        )
    except (ValueError, RecursionError):
        raise BodyError("bad_body") from None
    if not isinstance(obj, dict):
        raise BodyError("bad_body")
    return obj


def parse_json_object(body: bytes) -> dict:
    obj = parse_object(body)
    if not isinstance(obj.get("type"), str):
        raise BodyError("bad_body")
    return obj


def parse_hex(value: object, n_bytes: int) -> bytes | None:
    """The bytes of a lower-case hex string of exactly n_bytes, or None."""
    if isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{2 * n_bytes}}}", value):
        return bytes.fromhex(value)
    return None


def truncate_utf8(text: str, max_bytes: int) -> str:
    """Cuts text to at most max_bytes of UTF-8 without splitting a character."""
    data = text.encode("utf-8", errors="replace")[:max_bytes]
    return data.decode("utf-8", errors="ignore")


def _is_int(value: object) -> bool:
    return type(value) is int


def _bad(condition: bool) -> None:
    if condition:
        raise BodyError("bad_body")


def _combo(key: object, mods: object) -> tuple[int, int]:
    _bad(not (_is_int(key) and _is_int(mods)))
    _bad(not c.KEY_USAGE_MIN <= key <= c.KEY_USAGE_MAX or not 0 <= mods <= 0xFF)
    return key, mods


def _check_key(key: int, key_supported: Callable[[int], bool]) -> None:
    # Modifier usages never work as the key of a combo, whatever the mapping says.
    if key >= c.MODIFIER_USAGE_MIN or not key_supported(key):
        raise BodyError("unsupported_key")


def _text(value: object) -> str:
    _bad(not isinstance(value, str))
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise BodyError("bad_body") from None
    _bad(not 1 <= size <= c.TEXT_MAX_BYTES or _NOT_IN_TEXT.search(value) is not None)
    return value


def _pointer(obj: dict, limit: int) -> tuple[int, int]:
    dx, dy = obj["dx"], obj["dy"]
    _bad(not (_is_int(dx) and _is_int(dy)))
    _bad(abs(dx) > limit or abs(dy) > limit)
    return dx, dy


_REQUIRED = {
    "hello": (),
    "press": ("key", "mods"),
    "type": ("text",),
    "move": ("dx", "dy"),
    "button": ("button", "state"),
    "scroll": ("dx", "dy"),
    "unpair": (),
}
_OPTIONAL = {"type": ("open", "submit")}


def validate(
    obj: dict, key_supported: Callable[[int], bool], char_supported: Callable[[str], bool]
) -> Message:
    """Checks structure and ranges first, then key mapping, then character mapping."""
    kind = obj.get("type")
    _bad(not isinstance(kind, str))
    if kind not in _REQUIRED:
        raise BodyError("unknown_type")
    allowed = {"type", "challenge", *_REQUIRED[kind], *_OPTIONAL.get(kind, ())}
    _bad(not set(_REQUIRED[kind]) <= obj.keys() or not obj.keys() <= allowed)
    _bad("challenge" in obj and parse_hex(obj["challenge"], c.CHALLENGE_LEN) is None)

    if kind == "hello":
        return Hello()
    if kind == "unpair":
        return Unpair()
    if kind == "press":
        key, mods = _combo(obj["key"], obj["mods"])
        _check_key(key, key_supported)
        return Press(key, mods)
    if kind == "move":
        return Move(*_pointer(obj, c.MOVE_MAX))
    if kind == "scroll":
        return Scroll(*_pointer(obj, c.SCROLL_MAX))
    if kind == "button":
        _bad(obj["button"] not in ("left", "right") or obj["state"] not in ("down", "up"))
        return Button(obj["button"], obj["state"] == "down")

    text = _text(obj["text"])
    open_combo = None
    if "open" in obj:
        raw = obj["open"]
        _bad(not isinstance(raw, dict) or raw.keys() != {"key", "mods"})
        open_combo = _combo(raw["key"], raw["mods"])
    submit = obj.get("submit", False)
    _bad(type(submit) is not bool)
    if open_combo is not None:
        _check_key(open_combo[0], key_supported)
    if not all(char_supported(ch) for ch in text):
        raise BodyError("unsupported_char")
    return TypeText(text, open_combo, submit)


def encode_body(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def ok_body(sender_id: bytes, counter: int) -> dict:
    return {"type": "ok", "sender": sender_id.hex(), "counter": counter}


def welcome_body(sender_id: bytes, counter: int, plugin_id: bytes, hostname: str) -> dict:
    return {
        "type": "welcome",
        "sender": sender_id.hex(),
        "counter": counter,
        "pluginId": plugin_id.hex(),
        "maxVersion": c.MAX_VERSION,
        "hostname": truncate_utf8(hostname, c.HOSTNAME_MAX_BYTES),
    }


def error_body(
    sender_id: bytes, counter: int, code: str, retry_after_ms: int | None = None
) -> dict:
    body = {"type": "error", "sender": sender_id.hex(), "counter": counter, "error": code}
    if (code == "rate_limited") != (retry_after_ms is not None):
        raise ValueError("retryAfterMs goes with rate_limited and nothing else")
    if retry_after_ms is not None:
        if retry_after_ms < 1:
            raise ValueError("retryAfterMs must be at least 1")
        body["retryAfterMs"] = retry_after_ms
    return body
