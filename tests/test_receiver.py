# Tests for the receive procedure, replay window, rate limits and response sealing, including the receive vectors.
import json
import random as stdlib_random
from pathlib import Path

import pytest

from hotbar import constants as c
from hotbar import crypto, messages
from hotbar.envelope import Header, message_key, seal
from hotbar.receiver import Accepted, Challenge, PlainError, Receiver, ResponseSealer, SealedError, SenderState
from phone_client import TRANSPORT_ERROR, Sender, phone_receive

VECTORS = Path(__file__).parent / "vectors"
MASK = 2**64 - 1
NOW = 1_000_000
DEV_A, KEY_A = b"\xa1" * 16, b"\xa2" * 32
DEV_B, KEY_B = b"\xb1" * 16, b"\xb2" * 32
SID = b"\x11" * 8
PRESS = {"type": "press", "key": 4, "mods": 0}


def load_cases(file: str) -> list[dict]:
    return json.loads((VECTORS / file).read_text(encoding="utf-8"))["cases"]


def mapped(key: int) -> bool:
    return key < 0xE0


def typeable(_char: str) -> bool:
    return True


class Rand:
    """Deterministic stand-in for os.urandom: every call returns the next number as bytes."""

    def __init__(self):
        self.n = 0

    def __call__(self, size: int) -> bytes:
        self.n += 1
        return self.n.to_bytes(size, "big")


def make(keys=None, **kwargs):
    keys = {DEV_A: KEY_A} if keys is None else keys
    return Receiver(keys.get, mapped, typeable, random=Rand(), **kwargs), keys


def snap(receiver: Receiver):
    return (
        {k: (v.expires_at_ms, v.address) for k, v in receiver.challenges.items()},
        [(k, v.highest, v.bitmap) for k, v in receiver.senders.items()],
        dict(receiver.last_press_type_ms),
        {k: (v.tokens, v.updated_ms) for k, v in receiver.buckets.items()},
    )


def registered(receiver, device=DEV_A, key=KEY_A, sid=SID, highest=0, bitmap=1) -> Sender:
    """A sender the receiver already knows; its next counter is highest + 1."""
    receiver.senders[(device, sid)] = SenderState(highest, bitmap)
    sender = Sender(device, key, sender_id=sid)
    sender.counter = highest + 1
    return sender


def at(sender: Sender, counter: int, body: dict) -> bytes:
    sender.counter = counter
    return sender.seal(body)


def register(receiver, sender, body, now=NOW, address="10.0.0.1"):
    challenge = receiver.issue_challenge(address, now)
    return receiver.receive(sender.seal({**body, "challenge": challenge.hex()}), now)


def wire_of(key=KEY_A, device=DEV_A, body=b'{"type":"hello"}', *, version=1, direction=1, sid=SID, counter=1, salt=bytes(16)):
    return seal(key, Header(version, direction, device, sid, counter, salt), body)


def flip(wire: bytes, index: int) -> bytes:
    data = bytearray(wire)
    data[index] ^= 1
    return bytes(data)


def outcome_summary(outcome):
    if isinstance(outcome, Accepted):
        return "accept", outcome.message
    return outcome.code, None


# the receive vector file

def load_plugin_state(case):
    state = case["state"]
    keys = {bytes.fromhex(d["deviceId"]): bytes.fromhex(d["deviceKey"]) for d in state["devices"]}
    # the vector cases assume every non-modifier usage maps and every character can be typed
    receiver = Receiver(keys.get, lambda key: key < c.MODIFIER_USAGE_MIN, lambda char: True)
    for d in state["devices"]:
        if d["lastPressTypeAcceptedMs"] is not None:
            receiver.last_press_type_ms[bytes.fromhex(d["deviceId"])] = d["lastPressTypeAcceptedMs"]
    for s in state["senders"]:
        receiver.senders[(bytes.fromhex(s["deviceId"]), bytes.fromhex(s["senderId"]))] = SenderState(
            s["highest"], int(s["bitmap"], 16)
        )
    for ch in state["challenges"]:
        receiver.challenges[bytes.fromhex(ch["challenge"])] = Challenge(ch["expiresAtMs"], "")
    return receiver, keys


def dump_plugin_state(receiver, keys):
    return {
        "devices": [
            {
                "deviceId": device.hex(),
                "deviceKey": keys[device].hex(),
                "lastPressTypeAcceptedMs": receiver.last_press_type_ms.get(device),
            }
            for device in sorted(keys)
        ],
        "senders": [
            {"bitmap": f"{s.bitmap:016x}", "deviceId": k[0].hex(), "highest": s.highest, "senderId": k[1].hex()}
            for k, s in sorted(receiver.senders.items())
        ],
        "challenges": [
            {"challenge": ch.hex(), "expiresAtMs": v.expires_at_ms} for ch, v in sorted(receiver.challenges.items())
        ],
    }


def check_plugin_case(case):
    expect = case["expect"]
    receiver, keys = load_plugin_state(case)
    outcome = receiver.receive(bytes.fromhex(case["message"]), case["state"]["nowMs"])
    if isinstance(outcome, Accepted):
        got = dict(result="accept", error=None, sealed=None, response=None, transportError=None,
                   messageType=outcome.message.type_name)
    else:
        assert isinstance(outcome, (PlainError, SealedError))
        got = dict(result="reject", error=outcome.code, sealed=isinstance(outcome, SealedError),
                   response=outcome.body(), transportError=TRANSPORT_ERROR[outcome.code], messageType=None)
        if isinstance(outcome, SealedError):
            assert outcome.silent_on_stream is False
            assert (outcome.sender_id.hex(), outcome.counter) == (outcome.body()["sender"], outcome.body()["counter"])
    assert set(expect) == set(got) | {"retry", "after"}
    assert got == {key: expect[key] for key in got}
    assert expect["retry"] is False
    assert dump_plugin_state(receiver, keys) == expect["after"]


def check_phone_case(case):
    state, expect = case["state"], case["expect"]
    outstanding = {(bytes.fromhex(o["sender"]), o["counter"]) for o in state["outstanding"]}
    received = phone_receive(
        bytes.fromhex(case["message"]), bytes.fromhex(state["deviceId"]), bytes.fromhex(state["deviceKey"]), outstanding
    )
    assert set(expect) == {"result", "reason", "response", "after"}
    assert ("accept" if received.accepted else "drop") == expect["result"]
    assert received.reason == expect["reason"]
    assert received.response == expect["response"]
    after = [{"counter": counter, "sender": sender.hex()} for sender, counter in sorted(outstanding)]
    assert after == expect["after"]["outstanding"]


@pytest.mark.parametrize("case", load_cases("receive.json"), ids=lambda case: case["name"])
def test_receive_vector(case):
    if case["kind"] != "receive":
        pytest.fail(f"unknown vector kind {case['kind']!r}")
    if case["receiver"] == "plugin":
        check_plugin_case(case)
    elif case["receiver"] == "phone":
        check_phone_case(case)
    else:
        pytest.fail(f"unknown vector receiver {case['receiver']!r}")


def test_vector_wire_errors_are_all_in_the_phone_table():
    codes = {c_["expect"]["error"] for c_ in load_cases("receive.json") if c_["receiver"] == "plugin"} - {None}
    assert codes <= set(TRANSPORT_ERROR)


# plaintext failures, before authentication

PLAIN_WIRES = {
    "one byte short": lambda: bytes(c.MIN_ENVELOPE_LEN - 1),
    "one byte long": lambda: bytes(c.MAX_ENVELOPE_LEN + 1),
    "empty": lambda: b"",
    "version zero": lambda: wire_of(version=0),
    "version too new": lambda: wire_of(version=2),
    "version 255": lambda: wire_of(version=255),
    "direction plugin to phone": lambda: wire_of(direction=2),
    "direction zero": lambda: wire_of(direction=0),
    "direction 255": lambda: wire_of(direction=255),
    "unknown device": lambda: wire_of(device=b"\x99" * 16, key=b"\x98" * 32),
    "flipped tag": lambda: flip(wire_of(), -1),
    "flipped ciphertext": lambda: flip(wire_of(), c.HEADER_LEN),
    "flipped counter": lambda: flip(wire_of(), 33),
    "flipped salt": lambda: flip(wire_of(), 40),
    "wrong key": lambda: wire_of(key=b"\x77" * 32),
}


@pytest.mark.parametrize("name", PLAIN_WIRES)
def test_pre_authentication_failures_change_no_state(name):
    receiver, _ = make()
    registered(receiver)
    receiver.issue_challenge("10.0.0.1", NOW)
    receiver.last_press_type_ms[DEV_A] = NOW - 5
    before = snap(receiver)
    outcome = receiver.receive(PLAIN_WIRES[name](), NOW)
    assert isinstance(outcome, PlainError)
    assert snap(receiver) == before


@pytest.mark.parametrize(
    "name, code, status",
    [
        ("one byte short", "bad_message", 400),
        ("one byte long", "bad_message", 400),
        ("empty", "bad_message", 400),
        ("version zero", "bad_message", 400),
        ("version too new", "version_too_new", 426),
        ("version 255", "version_too_new", 426),
        ("direction plugin to phone", "bad_direction", 400),
        ("direction zero", "bad_direction", 400),
        ("direction 255", "bad_direction", 400),
        ("unknown device", "unknown_device", 401),
        ("flipped tag", "auth_failed", 401),
        ("flipped ciphertext", "auth_failed", 401),
        ("flipped counter", "auth_failed", 401),
        ("flipped salt", "auth_failed", 401),
        ("wrong key", "auth_failed", 401),
    ],
)
def test_pre_authentication_codes_and_statuses(name, code, status):
    receiver, _ = make()
    outcome = receiver.receive(PLAIN_WIRES[name](), NOW)
    assert outcome == PlainError(code)
    assert outcome.http_status == status


def test_plain_error_bodies():
    assert PlainError("bad_message").body() == {"error": "bad_message"}
    assert PlainError("version_too_new").body() == {"error": "version_too_new", "maxVersion": 1}
    assert PlainError("auth_failed").body() == {"error": "auth_failed"}
    assert {code: PlainError(code).http_status for code in ["pair_expired", "token_invalid", "confirm_failed", "rate_limited", "internal"]} == {
        "pair_expired": 410,
        "token_invalid": 401,
        "confirm_failed": 401,
        "rate_limited": 429,
        "internal": 500,
    }


def test_checks_run_in_order():
    receiver, _ = make()
    unknown = dict(device=b"\x99" * 16, key=b"\x98" * 32)
    assert receiver.receive(wire_of(version=0, direction=2, **unknown), NOW) == PlainError("bad_message")
    assert receiver.receive(wire_of(version=2, direction=2, **unknown), NOW) == PlainError("version_too_new")
    assert receiver.receive(wire_of(direction=2, **unknown), NOW) == PlainError("bad_direction")
    assert receiver.receive(flip(wire_of(**unknown), -1), NOW) == PlainError("unknown_device")


def test_length_limits_are_inclusive():
    receiver, _ = make()
    biggest = receiver.receive(wire_of(body=b"x" * c.BODY_MAX), NOW)
    assert isinstance(biggest, SealedError) and biggest.code == "bad_body"
    assert receiver.receive(bytes(c.MAX_ENVELOPE_LEN + 1), NOW) == PlainError("bad_message")


def test_an_authentic_message_with_an_empty_body_is_a_sealed_bad_body():
    receiver, _ = make()
    header = Header(1, 1, DEV_A, SID, 1, bytes(16))
    key, nonce = message_key(KEY_A, header.salt)
    ciphertext, tag = crypto.aead_seal(key, nonce, header.pack(), b"")
    wire = header.pack() + ciphertext + tag
    assert len(wire) == c.MIN_ENVELOPE_LEN
    outcome = receiver.receive(wire, NOW)
    assert isinstance(outcome, SealedError) and outcome.code == "bad_body"


# sealed failures at step 6

@pytest.mark.parametrize(
    "body",
    [b"not json", b"[1,2]", b"5", b"null", b'{"press":1}', b'{"type":5}', b'{"type":null}', b"\xff\xfe", b'{"type":"hello"} trailing'],
)
def test_unparseable_bodies_are_sealed_bad_body_and_change_no_state(body):
    receiver, _ = make()
    registered(receiver)
    receiver.issue_challenge("10.0.0.1", NOW)
    before = snap(receiver)
    outcome = receiver.receive(wire_of(body=body, counter=7), NOW)
    assert outcome == SealedError(DEV_A, SID, 7, "bad_body", None, False)
    assert outcome.body() == {"type": "error", "sender": SID.hex(), "counter": 7, "error": "bad_body"}
    assert snap(receiver) == before


def test_sealed_error_echoes_the_header_counter_even_at_the_extreme():
    receiver, _ = make()
    outcome = receiver.receive(wire_of(body=b"x", counter=2**64 - 1), NOW)
    assert outcome.body()["counter"] == 2**64 - 1


# accepted messages of every type

@pytest.mark.parametrize(
    "body, expected",
    [
        ({"type": "hello"}, messages.Hello()),
        ({"type": "press", "key": 30, "mods": 2}, messages.Press(30, 2)),
        ({"type": "type", "text": "hi"}, messages.TypeText("hi", None, False)),
        ({"type": "type", "text": "hi", "open": {"key": 40, "mods": 0}, "submit": True}, messages.TypeText("hi", (40, 0), True)),
        ({"type": "move", "dx": -3, "dy": 4}, messages.Move(-3, 4)),
        ({"type": "button", "button": "right", "state": "up"}, messages.Button("right", False)),
        ({"type": "scroll", "dx": 0, "dy": -120}, messages.Scroll(0, -120)),
        ({"type": "unpair"}, messages.Unpair()),
    ],
)
def test_every_message_type_is_accepted(body, expected):
    receiver, _ = make()
    sender = registered(receiver)
    outcome = receiver.receive(sender.seal(body), NOW)
    assert outcome == Accepted(DEV_A, SID, 1, expected)
    assert outcome.message.type_name == body["type"]


def test_a_registering_message_is_accepted_and_the_next_needs_no_challenge():
    receiver, _ = make()
    sender = Sender(DEV_A, KEY_A, sender_id=SID)
    outcome = register(receiver, sender, {"type": "hello"})
    assert outcome == Accepted(DEV_A, SID, 0, messages.Hello())
    assert receiver.receive(sender.seal(PRESS), NOW).counter == 1


def test_key_and_character_mapping_come_from_the_callbacks():
    receiver = Receiver({DEV_A: KEY_A}.get, lambda k: k != 30, lambda ch: ch != "ß", random=Rand())
    sender = registered(receiver)
    assert receiver.receive(sender.seal({"type": "press", "key": 30, "mods": 0}), NOW).code == "unsupported_key"
    assert receiver.receive(sender.seal({"type": "type", "text": "straße"}), NOW).code == "unsupported_char"
    assert isinstance(receiver.receive(sender.seal({"type": "type", "text": "strase"}), NOW), Accepted)


def test_validation_failures_are_sealed_with_the_validation_code():
    receiver, _ = make()
    sender = registered(receiver)
    for body, code in [
        ({"type": "launch"}, "unknown_type"),
        ({"type": "press", "key": 3, "mods": 0}, "bad_body"),
        ({"type": "press", "key": 0xE1, "mods": 0}, "unsupported_key"),
        ({"type": "move", "dx": 1, "dy": 1, "speed": 1}, "bad_body"),
    ]:
        outcome = receiver.receive(sender.seal(body), NOW)
        assert (outcome.code, outcome.retry_after_ms, outcome.silent_on_stream) == (code, None, False)


# registration

def test_unregistered_sender_without_a_challenge_is_challenge_required():
    receiver, _ = make()
    before = snap(receiver)
    outcome = receiver.receive(Sender(DEV_A, KEY_A, SID).seal(PRESS), NOW)
    assert outcome.code == "challenge_required"
    assert snap(receiver) == before


@pytest.mark.parametrize("challenge", ["AB" * 16, "ab" * 15, "ab" * 17, "zz" * 16, "", 5, None, True, ["ab" * 16], {"a": 1}])
def test_a_malformed_challenge_is_challenge_invalid(challenge):
    receiver, _ = make()
    receiver.issue_challenge("10.0.0.1", NOW)
    before = snap(receiver)
    outcome = receiver.receive(Sender(DEV_A, KEY_A, SID).seal({**PRESS, "challenge": challenge}), NOW)
    assert outcome.code == "challenge_invalid"
    assert snap(receiver) == before


def test_an_unknown_challenge_is_challenge_invalid():
    receiver, _ = make()
    outcome = receiver.receive(Sender(DEV_A, KEY_A, SID).seal({**PRESS, "challenge": "ab" * 16}), NOW)
    assert outcome.code == "challenge_invalid" and not receiver.senders


def test_challenge_expiry_boundary():
    for now, ok in ((NOW + c.CHALLENGE_TTL_MS - 1, True), (NOW + c.CHALLENGE_TTL_MS, False), (NOW + c.CHALLENGE_TTL_MS + 5000, False)):
        receiver, _ = make()
        challenge = receiver.issue_challenge("10.0.0.1", NOW)
        outcome = receiver.receive(Sender(DEV_A, KEY_A, SID).seal({**PRESS, "challenge": challenge.hex()}), now)
        assert isinstance(outcome, Accepted) is ok
        assert (challenge in receiver.challenges) is (not ok)


def test_a_challenge_is_single_use():
    receiver, _ = make()
    challenge = receiver.issue_challenge("10.0.0.1", NOW)
    first, second = Sender(DEV_A, KEY_A, b"\x01" * 8), Sender(DEV_A, KEY_A, b"\x02" * 8)
    assert isinstance(receiver.receive(first.seal({**PRESS, "challenge": challenge.hex()}), NOW), Accepted)
    outcome = receiver.receive(second.seal({**PRESS, "challenge": challenge.hex()}), NOW)
    assert outcome.code == "challenge_invalid"
    assert (DEV_A, b"\x02" * 8) not in receiver.senders


def test_a_captured_registering_message_cannot_be_delivered_twice():
    receiver, _ = make()
    challenge = receiver.issue_challenge("10.0.0.1", NOW)
    wire = Sender(DEV_A, KEY_A, SID).seal({**PRESS, "challenge": challenge.hex()})
    assert isinstance(receiver.receive(wire, NOW), Accepted)
    assert receiver.receive(wire, NOW + 100).code == "replayed"
    receiver.drop_sender(DEV_A, SID)
    assert receiver.receive(wire, NOW + 100).code == "challenge_invalid"


def test_a_challenge_is_not_bound_to_an_address_or_device():
    receiver, _ = make({DEV_A: KEY_A, DEV_B: KEY_B})
    challenge = receiver.issue_challenge("192.168.1.9", NOW)
    outcome = receiver.receive(Sender(DEV_B, KEY_B, SID).seal({**PRESS, "challenge": challenge.hex()}), NOW)
    assert isinstance(outcome, Accepted) and outcome.device_id == DEV_B


@pytest.mark.parametrize("counter", [0, 1, 7, 2**32 + 5, 2**64 - 1])
def test_registration_starts_with_a_full_window(counter):
    receiver, _ = make()
    sender = Sender(DEV_A, KEY_A, SID)
    sender.counter = counter
    assert isinstance(register(receiver, sender, PRESS), Accepted)
    state = receiver.senders[(DEV_A, SID)]
    assert (state.highest, state.bitmap) == (counter, MASK)
    receiver.last_press_type_ms.clear()
    for back, code in [(0, "replayed"), (1, "replayed"), (63, "replayed"), (64, "counter_too_old")]:
        if counter >= back:
            outcome = receiver.receive(at(sender, counter - back, PRESS), NOW)
            assert outcome.code == code, back
    if counter < 2**64 - 1:
        assert isinstance(receiver.receive(at(sender, counter + 1, PRESS), NOW), Accepted)


def test_registration_stays_when_the_body_is_refused_afterwards():
    receiver, _ = make()
    sender = Sender(DEV_A, KEY_A, SID)
    challenge = receiver.issue_challenge("10.0.0.1", NOW)
    outcome = receiver.receive(sender.seal({"type": "launch", "challenge": challenge.hex()}), NOW)
    assert outcome.code == "unknown_type"
    assert challenge not in receiver.challenges
    assert (receiver.senders[(DEV_A, SID)].highest, receiver.senders[(DEV_A, SID)].bitmap) == (0, MASK)
    assert isinstance(receiver.receive(sender.seal(PRESS), NOW), Accepted)


def test_registration_stays_when_the_message_is_rate_limited():
    receiver, _ = make()
    receiver.last_press_type_ms[DEV_A] = NOW - 10
    sender = Sender(DEV_A, KEY_A, SID)
    outcome = register(receiver, sender, PRESS)
    assert (outcome.code, outcome.retry_after_ms) == ("rate_limited", 90)
    assert (DEV_A, SID) in receiver.senders and not receiver.challenges


def test_a_challenge_on_a_registered_sender_is_ignored_and_spends_nothing():
    receiver, _ = make()
    sender = registered(receiver)
    challenge = receiver.issue_challenge("10.0.0.1", NOW)
    assert isinstance(receiver.receive(sender.seal({**PRESS, "challenge": challenge.hex()}), NOW), Accepted)
    assert challenge in receiver.challenges
    receiver.last_press_type_ms.clear()
    outcome = receiver.receive(sender.seal({**PRESS, "challenge": "not hex"}), NOW)
    assert outcome.code == "bad_body"
    assert receiver.senders[(DEV_A, SID)].highest == 2  # the counter is spent even so


# the replay window

WINDOW_ROWS = [
    # name, highest, bitmap, counter, expected code (None = accepted), highest after, bitmap after
    ("advance by one", 100, 0b1011, 101, None, 101, 0b10111),
    ("advance by two", 1000, 0xB4EA571386DCA3E5, 1002, None, 1002, 0xD3A95C4E1B728F95),
    ("advance by 63", 1000, 0xB4EA571386DCA3E5, 1063, None, 1063, 0x8000000000000001),
    ("advance by 64", 1000, 0xB4EA571386DCA3E5, 1064, None, 1064, 1),
    ("advance by 65", 1000, MASK, 1065, None, 1065, 1),
    ("advance far", 10, MASK, 2**64 - 1, None, 2**64 - 1, 1),
    ("top bit shifted out", 100, 0x8000000000000001, 101, None, 101, 0x3),
    ("equal to highest", 100, 0b1011, 100, "replayed", 100, 0b1011),
    ("seen inside window", 100, 0b1011, 99, "replayed", 100, 0b1011),
    ("seen at distance three", 100, 0b1011, 97, "replayed", 100, 0b1011),
    ("unseen inside window", 100, 0b1011, 98, None, 100, 0b1111),
    ("unseen at distance two, others kept", 100, 0b1001, 98, None, 100, 0b1101),
    ("unseen at the lower edge", 100, MASK >> 1, 37, None, 100, MASK),
    ("seen at the lower edge", 100, MASK, 37, "replayed", 100, MASK),
    ("one below the window", 100, MASK, 36, "counter_too_old", 100, MASK),
    ("far below the window", 100, 1, 3, "counter_too_old", 100, 1),
    ("near the top, advance by one", 2**64 - 2, 0b11, 2**64 - 1, None, 2**64 - 1, 0b111),
    ("at the top, equal", 2**64 - 1, 0b11, 2**64 - 1, "replayed", 2**64 - 1, 0b11),
    ("at the top, unseen below", 2**64 - 1, 0b1, 2**64 - 2, None, 2**64 - 1, 0b11),
    ("at the top, below the window", 2**64 - 1, MASK, 2**64 - 65, "counter_too_old", 2**64 - 1, MASK),
    ("small counters, highest zero", 0, 1, 0, "replayed", 0, 1),
    ("small counters, advance from zero", 0, 1, 1, None, 1, 0b11),
]


@pytest.mark.parametrize("row", WINDOW_ROWS, ids=[row[0] for row in WINDOW_ROWS])
def test_window_table(row):
    _, highest, bitmap, counter, code, highest_after, bitmap_after = row
    receiver, _ = make()
    sender = registered(receiver, highest=highest, bitmap=bitmap)
    outcome = receiver.receive(at(sender, counter, {"type": "hello"}), NOW)
    if code is None:
        assert isinstance(outcome, Accepted) and outcome.counter == counter
    else:
        assert outcome.code == code and outcome.counter == counter
    state = receiver.senders[(DEV_A, SID)]
    assert (state.highest, state.bitmap) == (highest_after, bitmap_after)


def test_window_agrees_with_a_set_based_model_on_random_counters():
    rng = stdlib_random.Random(1234)
    receiver, _ = make()
    sender = registered(receiver, highest=500, bitmap=MASK)
    seen, highest = set(range(437, 501)), 500
    for _ in range(600):
        counter = max(0, highest + rng.choice([-80, -64, -63, -30, -5, -2, -1, 0, 0, 1, 1, 2, 3, 10, 64, 100]))
        if counter > highest:
            expected = None
        elif highest - counter >= 64:
            expected = "counter_too_old"
        else:
            expected = "replayed" if counter in seen else None
        outcome = receiver.receive(at(sender, counter, {"type": "hello"}), NOW)
        assert (None if isinstance(outcome, Accepted) else outcome.code) == expected, counter
        if expected is None:
            seen.add(counter)
            highest = max(highest, counter)
    state = receiver.senders[(DEV_A, SID)]
    assert state.highest == highest
    assert all(bool(state.bitmap >> d & 1) == (highest - d in seen) for d in range(64))


def test_the_same_message_twice_is_replayed():
    receiver, _ = make()
    sender = registered(receiver)
    wire = sender.seal({"type": "hello"})
    assert isinstance(receiver.receive(wire, NOW), Accepted)
    assert receiver.receive(wire, NOW).code == "replayed"


def test_the_window_moves_only_after_the_message_opened():
    receiver, _ = make()
    sender = registered(receiver)
    wire = at(sender, 50, {"type": "hello"})
    assert receiver.receive(flip(wire, -1), NOW) == PlainError("auth_failed")
    assert receiver.senders[(DEV_A, SID)].highest == 0
    assert isinstance(receiver.receive(wire, NOW), Accepted)


def test_a_replay_with_a_damaged_tag_is_auth_failed_not_replayed():
    receiver, _ = make()
    sender = registered(receiver)
    wire = sender.seal({"type": "hello"})
    receiver.receive(wire, NOW)
    assert receiver.receive(flip(wire, -1), NOW) == PlainError("auth_failed")
    assert receiver.receive(flip(wire, -1), NOW) == PlainError("auth_failed")


def test_a_counter_that_passed_the_window_stays_spent_when_the_body_is_refused():
    receiver, _ = make()
    sender = registered(receiver)
    receiver.last_press_type_ms[DEV_A] = NOW - 10  # makes any press rate limited
    for body, code in [
        ({"type": "press", "key": 3, "mods": 0}, "bad_body"),
        ({"type": "press", "key": 0xE1, "mods": 0}, "unsupported_key"),
        ({"type": "launch"}, "unknown_type"),
        (PRESS, "rate_limited"),
    ]:
        counter = receiver.senders[(DEV_A, SID)].highest + 1
        assert receiver.receive(at(sender, counter, body), NOW).code == code
        assert receiver.receive(at(sender, counter, {"type": "hello"}), NOW).code == "replayed"


def test_a_counter_is_not_spent_when_the_body_does_not_parse():
    receiver, _ = make()
    registered(receiver)
    assert receiver.receive(wire_of(body=b"junk", counter=1), NOW).code == "bad_body"
    assert isinstance(receiver.receive(wire_of(body=b'{"type":"hello"}', counter=1, salt=b"\x01" * 16), NOW), Accepted)


# press and type gap

def test_gap_boundary_and_retry_after():
    for elapsed, retry in [(0, 100), (40, 60), (99, 1)]:
        receiver, _ = make()
        sender = registered(receiver)
        assert isinstance(receiver.receive(sender.seal(PRESS), NOW), Accepted)
        outcome = receiver.receive(sender.seal(PRESS), NOW + elapsed)
        assert outcome == SealedError(DEV_A, SID, 2, "rate_limited", retry, False)
        assert outcome.body()["retryAfterMs"] == retry
    receiver, _ = make()
    sender = registered(receiver)
    receiver.receive(sender.seal(PRESS), NOW)
    assert isinstance(receiver.receive(sender.seal(PRESS), NOW + 100), Accepted)


def test_a_rejected_message_does_not_move_the_gap_clock():
    receiver, _ = make()
    sender = registered(receiver)
    receiver.receive(sender.seal(PRESS), NOW)
    assert receiver.receive(sender.seal(PRESS), NOW + 50).code == "rate_limited"
    assert receiver.last_press_type_ms[DEV_A] == NOW
    assert isinstance(receiver.receive(sender.seal(PRESS), NOW + 100), Accepted)
    assert receiver.last_press_type_ms[DEV_A] == NOW + 100


def test_type_and_press_share_one_gap():
    receiver, _ = make()
    sender = registered(receiver)
    assert isinstance(receiver.receive(sender.seal({"type": "type", "text": "a"}), NOW), Accepted)
    assert receiver.receive(sender.seal(PRESS), NOW + 10).code == "rate_limited"
    assert isinstance(receiver.receive(sender.seal({"type": "type", "text": "b"}), NOW + 100), Accepted)
    assert receiver.receive(sender.seal({"type": "type", "text": "c"}), NOW + 150).code == "rate_limited"


def test_the_gap_is_per_device_across_all_its_senders():
    receiver, _ = make()
    first = registered(receiver, sid=b"\x01" * 8)
    second = registered(receiver, sid=b"\x02" * 8)
    assert isinstance(receiver.receive(first.seal(PRESS), NOW), Accepted)
    outcome = receiver.receive(second.seal(PRESS), NOW + 30)
    assert (outcome.code, outcome.retry_after_ms, outcome.sender_id) == ("rate_limited", 70, b"\x02" * 8)
    assert isinstance(receiver.receive(second.seal(PRESS), NOW + 100), Accepted)


def test_two_devices_do_not_share_a_gap():
    receiver, _ = make({DEV_A: KEY_A, DEV_B: KEY_B})
    a = registered(receiver, DEV_A, KEY_A)
    b = registered(receiver, DEV_B, KEY_B)
    assert isinstance(receiver.receive(a.seal(PRESS), NOW), Accepted)
    assert isinstance(receiver.receive(b.seal(PRESS), NOW), Accepted)
    assert receiver.receive(a.seal(PRESS), NOW + 1).code == "rate_limited"
    assert receiver.receive(b.seal(PRESS), NOW + 1).code == "rate_limited"


@pytest.mark.parametrize(
    "body",
    [
        {"type": "hello"},
        {"type": "unpair"},
        {"type": "button", "button": "left", "state": "down"},
        {"type": "move", "dx": 1, "dy": 1},
        {"type": "scroll", "dx": 0, "dy": 1},
    ],
)
def test_other_messages_ignore_the_gap_and_do_not_move_its_clock(body):
    receiver, _ = make()
    sender = registered(receiver)
    receiver.receive(sender.seal(PRESS), NOW)
    assert isinstance(receiver.receive(sender.seal(body), NOW + 1), Accepted)
    assert receiver.last_press_type_ms[DEV_A] == NOW
    assert isinstance(receiver.receive(sender.seal(PRESS), NOW + 100), Accepted)


def test_a_refused_press_does_not_start_the_gap():
    receiver, _ = make()
    sender = registered(receiver)
    assert receiver.receive(sender.seal({"type": "press", "key": 3, "mods": 0}), NOW).code == "bad_body"
    assert receiver.receive(sender.seal({"type": "press", "key": 0xE1, "mods": 0}), NOW).code == "unsupported_key"
    assert DEV_A not in receiver.last_press_type_ms
    assert isinstance(receiver.receive(sender.seal(PRESS), NOW + 1), Accepted)


# pointer bucket

def move(i: int = 0) -> dict:
    return {"type": "move", "dx": 1, "dy": i % 5}


def test_64_events_pass_at_once_and_the_65th_is_a_silent_drop():
    receiver, _ = make()
    sender = registered(receiver)
    for i in range(64):
        assert isinstance(receiver.receive(sender.seal(move(i)), NOW), Accepted), i
    outcome = receiver.receive(sender.seal(move()), NOW)
    assert outcome == SealedError(DEV_A, SID, 65, "rate_limited", 4, True)
    assert outcome.body()["retryAfterMs"] == 4


def test_refill_is_250_tokens_a_second():
    receiver, _ = make()
    sender = registered(receiver)
    for _ in range(64):
        receiver.receive(sender.seal(move()), NOW)
    outcome = receiver.receive(sender.seal(move()), NOW + 3)
    assert (outcome.code, outcome.retry_after_ms, outcome.silent_on_stream) == ("rate_limited", 1, True)
    assert isinstance(receiver.receive(sender.seal(move()), NOW + 4), Accepted)
    assert receiver.receive(sender.seal(move()), NOW + 4).retry_after_ms == 4


def test_a_steady_stream_gets_250_events_a_second_after_the_burst():
    receiver, _ = make()
    sender = registered(receiver)
    for _ in range(64):
        receiver.receive(sender.seal(move()), NOW)
    accepted = sum(isinstance(receiver.receive(sender.seal(move()), NOW + ms), Accepted) for ms in range(1, 1001))
    assert accepted == 250


def test_the_bucket_never_holds_more_than_64():
    receiver, _ = make()
    sender = registered(receiver)
    receiver.receive(sender.seal(move()), NOW)
    later = NOW + 3_600_000
    results = [isinstance(receiver.receive(sender.seal(move()), later), Accepted) for _ in range(66)]
    assert results == [True] * 64 + [False] * 2


def test_move_and_scroll_draw_from_one_bucket():
    receiver, _ = make()
    sender = registered(receiver)
    for i in range(64):
        body = move() if i % 2 else {"type": "scroll", "dx": 0, "dy": 120}
        assert isinstance(receiver.receive(sender.seal(body), NOW), Accepted)
    for body in (move(), {"type": "scroll", "dx": 0, "dy": 120}):
        assert receiver.receive(sender.seal(body), NOW).silent_on_stream is True


def test_the_bucket_is_per_device():
    receiver, _ = make({DEV_A: KEY_A, DEV_B: KEY_B})
    a = registered(receiver, DEV_A, KEY_A)
    b = registered(receiver, DEV_B, KEY_B)
    for _ in range(65):
        receiver.receive(a.seal(move()), NOW)
    assert receiver.receive(a.seal(move()), NOW).code == "rate_limited"
    assert all(isinstance(receiver.receive(b.seal(move()), NOW), Accepted) for _ in range(64))


@pytest.mark.parametrize(
    "body",
    [
        {"type": "button", "button": "left", "state": "up"},
        {"type": "hello"},
        {"type": "unpair"},
        PRESS,
        {"type": "type", "text": "a"},
    ],
)
def test_other_messages_never_draw_from_the_bucket(body):
    receiver, _ = make()
    sender = registered(receiver)
    for _ in range(64):
        receiver.receive(sender.seal(move()), NOW)
    receiver.last_press_type_ms.clear()
    assert isinstance(receiver.receive(sender.seal(body), NOW), Accepted)
    assert receiver.buckets[DEV_A].tokens == 0


def test_buttons_are_never_dropped():
    receiver, _ = make()
    sender = registered(receiver)
    for _ in range(100):
        receiver.receive(sender.seal(move()), NOW)
    for i in range(200):
        body = {"type": "button", "button": "left", "state": "down" if i % 2 == 0 else "up"}
        assert isinstance(receiver.receive(sender.seal(body), NOW), Accepted)


def test_refused_pointer_messages_do_not_draw_tokens():
    receiver, _ = make()
    sender = registered(receiver)
    for _ in range(100):
        assert receiver.receive(sender.seal({"type": "move", "dx": 5000, "dy": 0}), NOW).code == "bad_body"
    assert DEV_A not in receiver.buckets
    assert all(isinstance(receiver.receive(sender.seal(move()), NOW), Accepted) for _ in range(64))


def test_a_dropped_pointer_event_still_spends_its_counter():
    receiver, _ = make()
    sender = registered(receiver)
    for _ in range(64):
        receiver.receive(sender.seal(move()), NOW)
    assert receiver.receive(sender.seal(move()), NOW).code == "rate_limited"
    assert receiver.receive(at(sender, 65, {"type": "hello"}), NOW).code == "replayed"


def test_retry_after_is_rounded_up_and_at_least_one():
    receiver, _ = make()
    sender = registered(receiver)
    receiver.receive(sender.seal(move()), NOW)
    for tokens, retry in [(0, 4), (1, 4), (750, 1), (751, 1), (999, 1), (999 - 250, 2)]:
        receiver.buckets[DEV_A].tokens = tokens
        receiver.buckets[DEV_A].updated_ms = NOW
        assert receiver.receive(sender.seal(move()), NOW).retry_after_ms == retry, tokens


# the sender table

def fill_table(receiver, count, device=DEV_A):
    for i in range(count):
        receiver.senders[(device, i.to_bytes(8, "big"))] = SenderState(0, 1)


def test_the_sender_table_holds_512_and_evicts_the_least_recently_used():
    evicted = []
    receiver, _ = make(on_sender_evicted=lambda device, sender: evicted.append((device, sender)))
    fill_table(receiver, c.SENDER_TABLE_MAX - 1)
    assert isinstance(register(receiver, Sender(DEV_A, KEY_A, b"\xee" * 8), PRESS), Accepted)
    assert len(receiver.senders) == 512 and evicted == []
    receiver.last_press_type_ms.clear()
    assert isinstance(register(receiver, Sender(DEV_A, KEY_A, b"\xef" * 8), PRESS, now=NOW + 200), Accepted)
    assert len(receiver.senders) == 512
    assert evicted == [(DEV_A, (0).to_bytes(8, "big"))]
    assert (DEV_A, (0).to_bytes(8, "big")) not in receiver.senders


def test_use_refreshes_a_sender_so_the_next_oldest_goes():
    evicted = []
    receiver, _ = make(on_sender_evicted=lambda device, sender: evicted.append(sender))
    fill_table(receiver, c.SENDER_TABLE_MAX)
    oldest = Sender(DEV_A, KEY_A, (0).to_bytes(8, "big"))
    oldest.counter = 1
    assert isinstance(receiver.receive(oldest.seal({"type": "hello"}), NOW), Accepted)
    assert isinstance(register(receiver, Sender(DEV_A, KEY_A, b"\xee" * 8), {"type": "hello"}), Accepted)
    assert evicted == [(1).to_bytes(8, "big")]
    assert (DEV_A, (0).to_bytes(8, "big")) in receiver.senders


def test_an_evicted_sender_must_register_again_with_a_full_window():
    receiver, _ = make()
    fill_table(receiver, c.SENDER_TABLE_MAX)
    victim = Sender(DEV_A, KEY_A, (0).to_bytes(8, "big"))
    register(receiver, Sender(DEV_A, KEY_A, b"\xee" * 8), {"type": "hello"})
    victim.counter = 1
    assert receiver.receive(victim.seal({"type": "hello"}), NOW).code == "challenge_required"
    victim.counter = 100
    assert isinstance(register(receiver, victim, {"type": "hello"}, now=NOW + 1), Accepted)
    for old in (99, 40, 37):  # captured earlier messages with lower counters stay unusable
        assert receiver.receive(at(victim, old, {"type": "hello"}), NOW + 2).code == "replayed"
    assert receiver.receive(at(victim, 36, {"type": "hello"}), NOW + 2).code == "counter_too_old"


def test_dropping_a_sender_forgets_only_that_sender():
    receiver, _ = make()
    first = registered(receiver, sid=b"\x01" * 8)
    registered(receiver, sid=b"\x02" * 8)
    receiver.drop_sender(DEV_A, b"\x01" * 8)
    receiver.drop_sender(DEV_A, b"\x01" * 8)
    receiver.drop_sender(DEV_B, b"\x77" * 8)
    assert list(receiver.senders) == [(DEV_A, b"\x02" * 8)]
    assert receiver.receive(first.seal({"type": "hello"}), NOW).code == "challenge_required"


# two devices and revocation

def test_removing_one_device_leaves_the_other_working():
    receiver, keys = make({DEV_A: KEY_A, DEV_B: KEY_B})
    a = registered(receiver, DEV_A, KEY_A)
    b = registered(receiver, DEV_B, KEY_B)
    receiver.receive(a.seal(PRESS), NOW)
    receiver.receive(b.seal(PRESS), NOW)
    del keys[DEV_A]
    receiver.drop_device(DEV_A)
    assert receiver.receive(a.seal(PRESS), NOW + 500) == PlainError("unknown_device")
    assert isinstance(receiver.receive(b.seal(PRESS), NOW + 500), Accepted)
    assert list(receiver.senders) == [(DEV_B, SID)]
    assert DEV_A not in receiver.last_press_type_ms and DEV_A not in receiver.buckets
    assert DEV_B in receiver.last_press_type_ms


def test_a_removed_device_is_unknown_on_its_very_next_message_even_before_state_is_dropped():
    receiver, keys = make()
    sender = registered(receiver)
    assert isinstance(receiver.receive(sender.seal(PRESS), NOW), Accepted)
    del keys[DEV_A]
    assert receiver.receive(sender.seal(PRESS), NOW + 500) == PlainError("unknown_device")


def test_a_key_for_one_device_does_not_open_another_devices_messages():
    receiver, _ = make({DEV_A: KEY_A, DEV_B: KEY_B})
    wire = seal(KEY_B, Header(1, 1, DEV_A, SID, 1, bytes(16)), b'{"type":"hello"}')
    assert receiver.receive(wire, NOW) == PlainError("auth_failed")


def test_drop_device_resets_the_rate_limit_state():
    receiver, _ = make()
    sender = registered(receiver)
    for _ in range(64):
        receiver.receive(sender.seal(move()), NOW)
    receiver.receive(sender.seal(PRESS), NOW)
    receiver.drop_device(DEV_A)
    sender = registered(receiver)
    assert isinstance(receiver.receive(sender.seal(PRESS), NOW), Accepted)
    assert all(isinstance(receiver.receive(sender.seal(move()), NOW), Accepted) for _ in range(64))


# challenges

def test_issue_challenge_returns_16_bytes_valid_for_30_seconds():
    receiver, _ = make()
    challenge = receiver.issue_challenge("10.0.0.1", NOW)
    assert len(challenge) == c.CHALLENGE_LEN
    assert receiver.challenges[challenge] == Challenge(NOW + 30000, "10.0.0.1")


def test_per_address_cap_evicts_the_oldest_of_that_address():
    receiver, _ = make()
    other = receiver.issue_challenge("10.0.0.2", NOW)
    issued = [receiver.issue_challenge("10.0.0.1", NOW + i) for i in range(17)]
    mine = [ch for ch, v in receiver.challenges.items() if v.address == "10.0.0.1"]
    assert mine == issued[1:] and len(mine) == 16
    assert issued[0] not in receiver.challenges and other in receiver.challenges
    for _ in range(40):
        receiver.issue_challenge("10.0.0.1", NOW + 20)
    assert sum(v.address == "10.0.0.1" for v in receiver.challenges.values()) == 16


def test_total_cap_evicts_the_oldest_overall():
    receiver, _ = make()
    issued = [receiver.issue_challenge(f"10.0.{i // 16}.{i % 16}", NOW + i) for i in range(c.CHALLENGE_MAX_TOTAL)]
    assert len(receiver.challenges) == 256
    newest = receiver.issue_challenge("10.9.9.9", NOW + 300)
    assert len(receiver.challenges) == 256
    assert issued[0] not in receiver.challenges and issued[1] in receiver.challenges and newest in receiver.challenges
    receiver.issue_challenge("10.9.9.9", NOW + 301)
    assert issued[1] not in receiver.challenges and issued[2] in receiver.challenges


@pytest.mark.parametrize("order", ["round robin", "one address at a time"])
def test_total_cap_never_takes_a_challenge_from_an_address_holding_fewer_than_the_flooders(order):
    receiver, _ = make()
    phone = receiver.issue_challenge("10.0.0.99", NOW)
    flooders = 17
    sequence = range(flooders * c.CHALLENGE_MAX_PER_ADDRESS)
    owners = [i % flooders if order == "round robin" else i // c.CHALLENGE_MAX_PER_ADDRESS for i in sequence]
    for i, owner in zip(sequence, owners, strict=True):
        receiver.issue_challenge(f"10.1.0.{owner}", NOW + 1 + i)
        assert phone in receiver.challenges
    assert len(receiver.challenges) == c.CHALLENGE_MAX_TOTAL
    held = [sum(v.address == f"10.1.0.{n}" for v in receiver.challenges.values()) for n in range(flooders)]
    assert max(held) <= c.CHALLENGE_MAX_PER_ADDRESS and sum(held) == c.CHALLENGE_MAX_TOTAL - 1


def test_total_cap_tie_evicts_the_oldest_challenge_overall():
    receiver, _ = make()
    addresses = [f"10.0.0.{n}" for n in range(c.CHALLENGE_MAX_TOTAL // 2)]
    issued = [receiver.issue_challenge(address, NOW + i) for i, address in enumerate(addresses * 2)]
    assert len(receiver.challenges) == c.CHALLENGE_MAX_TOTAL
    receiver.issue_challenge("10.9.9.9", NOW + 300)
    assert issued[0] not in receiver.challenges and issued[1] in receiver.challenges
    receiver.issue_challenge("10.9.9.9", NOW + 301)
    assert issued[1] not in receiver.challenges and issued[2] in receiver.challenges


def test_total_cap_tie_goes_to_the_address_whose_oldest_challenge_comes_first():
    receiver, _ = make()
    single = receiver.issue_challenge("10.0.0.1", NOW)
    a1 = receiver.issue_challenge("10.0.0.2", NOW + 1)
    b1 = receiver.issue_challenge("10.0.0.3", NOW + 2)
    b2 = receiver.issue_challenge("10.0.0.3", NOW + 3)
    a2 = receiver.issue_challenge("10.0.0.2", NOW + 4)
    for n in range(c.CHALLENGE_MAX_TOTAL - 5):
        receiver.issue_challenge(f"10.1.{n // 256}.{n % 256}", NOW + 5 + n)
    assert len(receiver.challenges) == c.CHALLENGE_MAX_TOTAL
    # Two addresses hold two each and the rest hold one: the single older challenge is not the one that goes.
    receiver.issue_challenge("10.9.9.1", NOW + 300)
    assert a1 not in receiver.challenges and {single, a2, b1, b2} <= receiver.challenges.keys()
    receiver.issue_challenge("10.9.9.2", NOW + 301)
    assert b1 not in receiver.challenges and {single, a2, b2} <= receiver.challenges.keys()
    receiver.issue_challenge("10.9.9.3", NOW + 302)
    assert single not in receiver.challenges and {a2, b2} <= receiver.challenges.keys()


def test_an_evicted_challenge_no_longer_registers():
    receiver, _ = make()
    first = receiver.issue_challenge("10.0.0.1", NOW)
    for i in range(16):
        receiver.issue_challenge("10.0.0.1", NOW + 1 + i)
    outcome = receiver.receive(Sender(DEV_A, KEY_A, SID).seal({**PRESS, "challenge": first.hex()}), NOW + 20)
    assert outcome.code == "challenge_invalid"


def test_issuing_purges_expired_challenges_only():
    receiver, _ = make()
    old = [receiver.issue_challenge("10.0.0.1", NOW) for _ in range(3)]
    receiver.issue_challenge("10.0.0.1", NOW + c.CHALLENGE_TTL_MS - 1)
    assert all(ch in receiver.challenges for ch in old)
    receiver.issue_challenge("10.0.0.1", NOW + c.CHALLENGE_TTL_MS)
    assert not any(ch in receiver.challenges for ch in old)
    assert len(receiver.challenges) == 2


def test_expired_challenges_do_not_count_against_the_caps():
    receiver, _ = make()
    old = [receiver.issue_challenge("10.0.0.1", NOW) for _ in range(16)]
    live = receiver.issue_challenge("10.0.0.1", NOW + c.CHALLENGE_TTL_MS + 1)
    assert not any(ch in receiver.challenges for ch in old) and live in receiver.challenges
    assert len(receiver.challenges) == 1


def test_receive_never_purges_challenges():
    receiver, _ = make()
    receiver.issue_challenge("10.0.0.1", NOW)
    registered(receiver)
    receiver.receive(wire_of(counter=1), NOW + 10 * c.CHALLENGE_TTL_MS)
    assert len(receiver.challenges) == 1


# sealing the plugin's answers

def test_response_sealer_output_opens_on_the_phone():
    sealer = ResponseSealer(KEY_A, DEV_A, random=Rand())
    request = (b"\x55" * 8, 9)
    wire = sealer.seal(messages.ok_body(*request))
    received = phone_receive(wire, DEV_A, KEY_A, {request})
    assert received.accepted and received.response == messages.ok_body(*request)


def test_response_sealer_headers():
    random = Rand()
    sealer = ResponseSealer(KEY_A, DEV_A, random=random)
    assert sealer.sender_id == (1).to_bytes(8, "big")
    wires = [sealer.seal(messages.ok_body(b"\x55" * 8, n)) for n in range(3)]
    headers = [Header.parse(wire) for wire in wires]
    assert [h.counter for h in headers] == [0, 1, 2]
    assert {h.direction for h in headers} == {c.DIR_PLUGIN_TO_PHONE}
    assert {h.version for h in headers} == {1} and {h.device_id for h in headers} == {DEV_A}
    assert {h.sender_id for h in headers} == {sealer.sender_id}
    assert len({h.salt for h in headers}) == 3
    assert len({wire[c.HEADER_LEN :] for wire in wires}) == 3


def test_response_sealers_use_different_random_sender_ids():
    assert ResponseSealer(KEY_A, DEV_A).sender_id != ResponseSealer(KEY_A, DEV_A).sender_id


def test_a_sealed_answer_is_not_a_valid_phone_message():
    receiver, _ = make()
    wire = ResponseSealer(KEY_A, DEV_A).seal(messages.ok_body(SID, 1))
    assert receiver.receive(wire, NOW) == PlainError("bad_direction")


def test_every_answer_body_round_trips_through_the_phone():
    sealer = ResponseSealer(KEY_A, DEV_A)
    for body in [
        messages.ok_body(SID, 1),
        messages.welcome_body(SID, 2, b"\xaa" * 16, "Steam Deck"),
        messages.error_body(SID, 3, "rate_limited", 40),
        messages.error_body(SID, 4, "replayed"),
        SealedError(DEV_A, SID, 5, "unsupported_char", None, False).body(),
    ]:
        outstanding = {(SID, body["counter"])}
        received = phone_receive(sealer.seal(body), DEV_A, KEY_A, outstanding)
        assert received.accepted and received.response == body and not outstanding


# the test phone's receive rules

def phone_wire(body: dict, *, key=KEY_A, device=DEV_A, version=1, direction=2, counter=0) -> bytes:
    header = Header(version, direction, device, b"\x66" * 8, counter, bytes(16))
    return seal(key, header, messages.encode_body(body))


def test_phone_drops_with_the_right_reason_and_keeps_its_outstanding_request():
    request = (SID, 1)
    good = messages.ok_body(*request)
    cases = {
        "length": bytes(c.MIN_ENVELOPE_LEN - 1),
        "version": phone_wire(good, version=2),
        "direction": phone_wire(good, direction=1),
        "device": phone_wire(good, device=DEV_B),
        "auth": flip(phone_wire(good), -1),
        "body": phone_wire({"type": "ok", "sender": SID.hex(), "counter": 1, "extra": 1}),
        "not_outstanding": phone_wire(messages.ok_body(SID, 2)),
    }
    for reason, wire in cases.items():
        outstanding = {request}
        received = phone_receive(wire, DEV_A, KEY_A, outstanding)
        assert (received.accepted, received.reason, received.response) == (False, reason, None), reason
        assert outstanding == {request}
    assert phone_receive(bytes(c.MAX_ENVELOPE_LEN + 1), DEV_A, KEY_A, {request}).reason == "length"


@pytest.mark.parametrize(
    "body",
    [
        {"type": "launch", "sender": SID.hex(), "counter": 1},
        {"type": "ok", "sender": SID.hex()},
        {"type": "ok", "sender": SID.hex(), "counter": True},
        {"type": "ok", "sender": SID.hex(), "counter": 1.0},
        {"type": "ok", "sender": "ABABABABABABABAB", "counter": 1},
        {"type": "welcome", "sender": SID.hex(), "counter": 1, "pluginId": "aa" * 16, "maxVersion": 1},
        {"type": "welcome", "sender": SID.hex(), "counter": 1, "pluginId": "aa" * 16, "maxVersion": 1, "hostname": "h" * 64},
        {"type": "error", "sender": SID.hex(), "counter": 1, "error": "no_such_code"},
        {"type": "error", "sender": SID.hex(), "counter": 1, "error": "rate_limited"},
        {"type": "error", "sender": SID.hex(), "counter": 1, "error": "rate_limited", "retryAfterMs": 0},
        {"type": "error", "sender": SID.hex(), "counter": 1, "error": "bad_body", "retryAfterMs": 5},
        {"type": "error", "sender": SID.hex(), "counter": 1, "error": ["bad_body"]},
    ],
)
def test_phone_drops_answers_that_break_the_body_rules(body):
    outstanding = {(SID, 1)}
    assert phone_receive(phone_wire(body), DEV_A, KEY_A, outstanding).reason == "body"
    assert outstanding == {(SID, 1)}


def test_phone_accepts_an_answer_once():
    outstanding = {(SID, 1)}
    wire = phone_wire(messages.ok_body(SID, 1))
    assert phone_receive(wire, DEV_A, KEY_A, outstanding).accepted
    assert phone_receive(wire, DEV_A, KEY_A, outstanding).reason == "not_outstanding"


def test_transport_error_table():
    assert TRANSPORT_ERROR["replayed"] is None
    assert {name for name in TRANSPORT_ERROR.values() if name} == {
        "failed", "versionMismatch", "unauthorized", "rateLimited", "unsupported"
    }
    assert [TRANSPORT_ERROR[x] for x in ("challenge_required", "challenge_invalid", "counter_too_old", "bad_direction")] == ["failed"] * 4


# no logging

@pytest.mark.parametrize("module", ["envelope", "pairing", "store", "messages", "receiver"])
def test_modules_neither_log_nor_print(module):
    source = (Path(__file__).parent.parent / "py_modules" / "hotbar" / f"{module}.py").read_text()
    assert "logging" not in source and "logger" not in source and "print(" not in source
