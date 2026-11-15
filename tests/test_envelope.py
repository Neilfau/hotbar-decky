# Tests for the envelope header, the per-message key and sealing, including the vector files.
import json
from pathlib import Path

import pytest

from hotbar import constants as c
from hotbar.crypto import AuthenticationError
from hotbar.envelope import Header, message_key, open_envelope, seal

VECTORS = Path(__file__).parent / "vectors"
KEY = bytes(range(32))
HEADER = Header(1, 1, bytes(range(16)), bytes(range(8)), 5, bytes(range(16)))


def load_cases(file: str) -> list[dict]:
    return json.loads((VECTORS / file).read_text(encoding="utf-8"))["cases"]


def test_message_key_vector_kinds_are_known():
    assert {case["kind"] for case in load_cases("message-keys.json")} == {"message-key"}
    assert {case["kind"] for case in load_cases("envelopes.json")} == {"envelope"}


@pytest.mark.parametrize("case", load_cases("message-keys.json"), ids=lambda case: case["name"])
def test_message_key_vector(case):
    if case["kind"] != "message-key":
        pytest.fail(f"unknown vector kind {case['kind']!r}")
    key, nonce = message_key(bytes.fromhex(case["deviceKey"]), bytes.fromhex(case["salt"]))
    assert key.hex() == case["key"]
    assert nonce.hex() == case["nonce"]
    assert (key + nonce).hex() == case["okm"]


@pytest.mark.parametrize("case", load_cases("envelopes.json"), ids=lambda case: case["name"])
def test_envelope_vector(case):
    if case["kind"] != "envelope":
        pytest.fail(f"unknown vector kind {case['kind']!r}")
    fields = case["header"]
    header = Header(
        fields["version"],
        fields["direction"],
        bytes.fromhex(fields["deviceId"]),
        bytes.fromhex(fields["senderId"]),
        fields["counter"],
        bytes.fromhex(fields["salt"]),
    )
    device_key = bytes.fromhex(case["deviceKey"])
    assert header.pack().hex() == case["headerBytes"]
    assert Header.parse(bytes.fromhex(case["headerBytes"])) == header

    key, nonce = message_key(device_key, header.salt)
    assert key.hex() == case["messageKey"]
    assert nonce.hex() == case["messageNonce"]

    wire = seal(device_key, header, case["body"].encode("utf-8"))
    assert wire.hex() == case["wire"]
    assert wire[c.HEADER_LEN : -c.TAG_LEN].hex() == case["ciphertext"]
    assert wire[-c.TAG_LEN :].hex() == case["tag"]

    opened_header, body = open_envelope(device_key, bytes.fromhex(case["wire"]))
    assert opened_header == header
    assert body.decode("utf-8") == case["body"]


def test_header_round_trip_with_extreme_values():
    header = Header(255, 2, b"\xff" * 16, b"\x00" * 8, 2**64 - 1, b"\xaa" * 16)
    packed = header.pack()
    assert len(packed) == c.HEADER_LEN
    assert Header.parse(packed + b"trailing bytes are ignored") == header


def test_header_counter_is_eight_bytes_big_endian():
    packed = Header(1, 1, bytes(16), bytes(8), 0x0102030405060708, bytes(16)).pack()
    assert packed[26:34] == bytes([1, 2, 3, 4, 5, 6, 7, 8])


def test_header_parse_does_not_judge_version_or_direction():
    header = Header.parse(Header(0, 9, bytes(16), bytes(8), 0, bytes(16)).pack())
    assert (header.version, header.direction) == (0, 9)


def test_header_parse_rejects_short_input():
    with pytest.raises(ValueError):
        Header.parse(HEADER.pack()[:-1])


@pytest.mark.parametrize(
    "fields",
    [
        dict(device_id=bytes(15)),
        dict(device_id=bytes(17)),
        dict(sender_id=bytes(7)),
        dict(sender_id=bytes(9)),
        dict(salt=bytes(15)),
        dict(salt=bytes(17)),
        dict(counter=-1),
        dict(counter=2**64),
        dict(version=256),
        dict(direction=-1),
    ],
)
def test_header_rejects_bad_fields(fields):
    args = dict(version=1, direction=1, device_id=bytes(16), sender_id=bytes(8), counter=0, salt=bytes(16))
    with pytest.raises(ValueError):
        Header(**{**args, **fields})


def test_message_key_sizes_and_salt_dependence():
    key_a, nonce_a = message_key(KEY, bytes(16))
    key_b, nonce_b = message_key(KEY, b"\x01" * 16)
    assert (len(key_a), len(nonce_a)) == (32, 12)
    assert key_a != key_b and nonce_a != nonce_b
    assert message_key(b"\x01" * 32, bytes(16)) != (key_a, nonce_a)


def test_seal_open_round_trip_at_both_body_limits():
    for size in (1, c.BODY_MAX):
        wire = seal(KEY, HEADER, b"x" * size)
        assert len(wire) == c.HEADER_LEN + size + c.TAG_LEN
        assert open_envelope(KEY, wire) == (HEADER, b"x" * size)
    assert len(seal(KEY, HEADER, b"x")) == c.MIN_ENVELOPE_LEN + 1
    assert len(seal(KEY, HEADER, b"x" * c.BODY_MAX)) == c.MAX_ENVELOPE_LEN


@pytest.mark.parametrize("size", [0, c.BODY_MAX + 1])
def test_seal_rejects_body_outside_limits(size):
    with pytest.raises(ValueError):
        seal(KEY, HEADER, b"x" * size)


def test_fresh_salt_gives_different_wire_for_the_same_body():
    other = Header(1, 1, HEADER.device_id, HEADER.sender_id, HEADER.counter, b"\x09" * 16)
    first, second = seal(KEY, HEADER, b"same body"), seal(KEY, other, b"same body")
    assert first[c.HEADER_LEN :] != second[c.HEADER_LEN :]


@pytest.mark.parametrize("position", [0, 1, 2, 17, 18, 25, 26, 33, 34, 49, 50, 60, -17, -1])
def test_any_changed_byte_fails_authentication(position):
    wire = bytearray(seal(KEY, HEADER, b"hello world body"))
    wire[position] ^= 0x01
    with pytest.raises(AuthenticationError):
        open_envelope(KEY, bytes(wire))


def test_wrong_device_key_fails_authentication():
    with pytest.raises(AuthenticationError):
        open_envelope(b"\x01" * 32, seal(KEY, HEADER, b"body"))


@pytest.mark.parametrize("size", [c.MIN_ENVELOPE_LEN - 1, c.MAX_ENVELOPE_LEN + 1])
def test_open_rejects_wire_outside_length_limits(size):
    with pytest.raises(ValueError):
        open_envelope(KEY, bytes(size))
