# Tests for the pairing session and the test phone, including the pairing vector file.
import hashlib
import json
from pathlib import Path

import pytest

from hotbar import constants as c
from hotbar import pairing
from hotbar.pairing import PairingSession, build_qr_uri, reject_confirm_without_session, reject_without_session
from hotbar.store import Device, DeviceStore, StoreError
from phone_client import PairingFailure, PhonePairing, parse_uri

VECTORS = Path(__file__).parent / "vectors"
PLUGIN_ID = b"\xb0" * 16
HOST, PORT, HOSTNAME = "192.168.1.50", 48321, "Steam Deck"
WALL = 1_700_000_000.9
T0 = 1000.0


def load_cases(file: str) -> list[dict]:
    return json.loads((VECTORS / file).read_text(encoding="utf-8"))["cases"]


def dump(obj) -> bytes:
    return json.dumps(obj).encode()


def scripted(*values: bytes):
    """A random source that hands out the given values in order and checks each requested size."""
    queue = list(values)

    def random(size: int) -> bytes:
        value = queue.pop(0)
        assert len(value) == size
        return value

    random.left = queue
    return random


class Rand:
    """Deterministic stand-in for os.urandom: every call returns a fresh fill byte."""

    def __init__(self):
        self.fill = 1

    def __call__(self, size: int) -> bytes:
        self.fill += 1
        return bytes([self.fill]) * size


def make_session(random=None, now_s=T0, hostname=HOSTNAME) -> PairingSession:
    return PairingSession(
        plugin_id=PLUGIN_ID,
        host=HOST,
        port=PORT,
        hostname=hostname,
        now_s=now_s,
        random=random or Rand(),
        wall_clock=lambda: WALL,
    )


def make_phone(session: PairingSession, name="Test iPhone") -> PhonePairing:
    return PhonePairing(session.uri, name, b"\x42" * 32, b"\x43" * 16)


def paired(now_s=T0 + 1, **kwargs):
    """A session whose pair request succeeded: returns the session, the phone and the confirm body."""
    session = make_session(**kwargs)
    phone = make_phone(session)
    status, response = session.pair(dump(phone.pair_request()), now_s, set())
    assert status == 200
    return session, phone, dump(phone.on_pair_response(response))


def expired(code: str, status: int):
    return status, {"error": code}


# the pairing vector file

def check_vector_plugin_side(case):
    inputs, derived, messages = case["inputs"], case["derived"], case["messages"]
    session = PairingSession(
        plugin_id=bytes.fromhex(inputs["pluginId"]),
        host=inputs["host"],
        port=inputs["port"],
        hostname=inputs["hostname"],
        now_s=0.0,
        # draw order: private key, token, secret, then plugin nonce and device id at pair time
        random=scripted(*(bytes.fromhex(inputs[k]) for k in ("pluginPrivate", "token", "secret", "pluginNonce", "deviceId"))),
        wall_clock=lambda: WALL,
    )
    assert session.uri == derived["qrUri"]
    assert parse_uri(session.uri).fingerprint.hex() == derived["fingerprint"]

    status, response = session.pair(dump(messages["pairRequest"]), 1.0, set())
    assert (status, response) == (200, messages["pairResponse"])
    assert response["pluginPublic"] == derived["pluginPublic"]
    assert hashlib.sha256(bytes.fromhex(response["pluginPublic"])).digest()[:16].hex() == derived["fingerprint"]

    committed: list[Device] = []
    status, response = session.confirm(dump(messages["confirmRequest"]), 2.0, committed.append)
    assert (status, response) == (200, messages["confirmResponse"])
    assert response["confirm"] == derived["confirmPlugin"]
    assert committed == [
        Device(bytes.fromhex(inputs["deviceId"]), bytes.fromhex(derived["deviceKey"]), inputs["phoneName"], int(WALL))
    ]
    assert session.succeeded and not session.is_active(2.0)


def check_vector_phone_side(case):
    inputs, derived, messages = case["inputs"], case["derived"], case["messages"]
    phone = PhonePairing(
        derived["qrUri"],
        inputs["phoneName"],
        bytes.fromhex(inputs["phonePrivate"]),
        bytes.fromhex(inputs["phoneNonce"]),
    )
    assert phone.uri.host == inputs["host"] and phone.uri.port == inputs["port"]
    assert phone.uri.name == inputs["hostname"]
    assert phone.uri.token.hex() == inputs["token"] and phone.uri.secret.hex() == inputs["secret"]
    assert phone.uri.plugin_id.hex() == inputs["pluginId"]
    assert phone.public.hex() == derived["phonePublic"]
    assert phone.pair_request() == messages["pairRequest"]
    assert phone.on_pair_response(messages["pairResponse"]) == messages["confirmRequest"]
    assert phone.device_key.hex() == derived["deviceKey"]
    assert phone.device_id.hex() == inputs["deviceId"]
    phone.verify_confirm(messages["confirmResponse"])


def check_vector_low_order(case):
    inputs = case["inputs"]
    assert case["expect"] == {"reject": True}
    # plugin side: the phone's public key is the low-order point
    random = scripted(bytes.fromhex(inputs["ownPrivate"]), b"\x01" * 16, b"\x02" * 32, b"\x03" * 16, b"\x04" * 16)
    session = make_session(random)
    request = {"token": "01" * 16, "phonePublic": inputs["peerPublic"], "phoneNonce": "05" * 16, "name": "P"}
    assert session.pair(dump(request), T0 + 1, set()) == expired("bad_message", 400)
    assert not session.is_active(T0 + 1)
    assert reject_without_session(dump(request)) == expired("pair_expired", 410)
    assert session.pair(dump(request), T0 + 2, set()) == expired("pair_expired", 410)
    # phone side: the plugin's public key is the low-order point (its fingerprint matches the QR)
    uri = build_qr_uri(
        host=HOST,
        port=PORT,
        token=bytes(16),
        secret=bytes(32),
        fingerprint=hashlib.sha256(bytes.fromhex(inputs["peerPublic"])).digest()[:16],
        plugin_id=PLUGIN_ID,
        hostname="deck",
    )
    phone = PhonePairing(uri, "P", bytes.fromhex(inputs["ownPrivate"]), bytes(16))
    response = {"pluginPublic": inputs["peerPublic"], "pluginNonce": "00" * 16, "deviceId": "00" * 16}
    with pytest.raises(PairingFailure, match="low order"):
        phone.on_pair_response(response)
    assert phone.device_key is None


def check_vector_fingerprint(case):
    inputs, derived = case["inputs"], case["derived"]
    assert case["expect"] == {"reject": True}
    assert hashlib.sha256(bytes.fromhex(inputs["pluginPublic"])).digest()[:16].hex() == derived["fingerprint"]
    assert inputs["qrFingerprint"] != derived["fingerprint"]
    uri = build_qr_uri(
        host=HOST,
        port=PORT,
        token=bytes(16),
        secret=bytes(32),
        fingerprint=bytes.fromhex(inputs["qrFingerprint"]),
        plugin_id=PLUGIN_ID,
        hostname="deck",
    )
    phone = PhonePairing(uri, "P", b"\x01" * 32, bytes(16))
    response = {"pluginPublic": inputs["pluginPublic"], "pluginNonce": "00" * 16, "deviceId": "00" * 16}
    with pytest.raises(PairingFailure, match="fingerprint"):
        phone.on_pair_response(response)
    assert phone.device_key is None and phone.device_id is None


@pytest.mark.parametrize("case", load_cases("pairing.json"), ids=lambda case: case["name"])
def test_pairing_vector(case):
    if case["kind"] == "pairing":
        check_vector_plugin_side(case)
        check_vector_phone_side(case)
    elif case["kind"] == "pairing-reject" and case["check"] == "low-order":
        check_vector_low_order(case)
    elif case["kind"] == "pairing-reject" and case["check"] == "fingerprint":
        check_vector_fingerprint(case)
    else:
        pytest.fail(f"unknown vector kind {case['kind']!r} / check {case.get('check')!r}")


# the QR link

def test_qr_uri_matches_the_vector_inputs_and_parameter_order():
    inputs = load_cases("pairing.json")[0]["inputs"]
    derived = load_cases("pairing.json")[0]["derived"]
    uri = build_qr_uri(
        host=inputs["host"],
        port=inputs["port"],
        token=bytes.fromhex(inputs["token"]),
        secret=bytes.fromhex(inputs["secret"]),
        fingerprint=bytes.fromhex(derived["fingerprint"]),
        plugin_id=bytes.fromhex(inputs["pluginId"]),
        hostname=inputs["hostname"],
    )
    assert uri == derived["qrUri"]
    assert uri.startswith("hotbar://pair?v=1&host=")
    assert [part.split("=")[0] for part in uri.split("?")[1].split("&")] == [
        "v", "host", "port", "token", "secret", "fp", "pid", "name"
    ]


@pytest.mark.parametrize(
    "hostname, decoded",
    [
        ("deck", "deck"),
        ("a" * 63, "a" * 63),
        ("a" * 64, "a" * 63),
        ("é" * 40, "é" * 31),
        ("ab" + "😀" * 20, "ab" + "😀" * 15),
        ("with space/slash?&=#%", "with space/slash?&=#%"),
        ("A-z.0_9~", "A-z.0_9~"),
    ],
)
def test_qr_hostname_is_cut_on_a_character_boundary_and_percent_encoded(hostname, decoded):
    uri = make_session(hostname=hostname).uri
    name = uri.rsplit("&name=", 1)[1]
    assert len(name) > 0 and all(ch.isalnum() or ch in "-._~%" for ch in name)
    assert parse_uri(uri).name == decoded
    assert len(decoded.encode()) <= 63


def test_qr_percent_escapes_use_upper_case_hex():
    assert make_session(hostname="é ").uri.endswith("&name=%C3%A9%20")


@pytest.mark.parametrize(
    "changes",
    [
        dict(host="deck.local"),
        dict(host="1.2.3"),
        dict(host="01.2.3.4"),
        dict(host="256.1.1.1"),
        dict(host="::1"),
        dict(host=" 1.2.3.4"),
        dict(port=0),
        dict(port=65536),
        dict(port=True),
        dict(hostname=""),
    ],
)
def test_qr_uri_refuses_values_the_phone_would_refuse(changes):
    args = dict(host=HOST, port=PORT, token=bytes(16), secret=bytes(32), fingerprint=bytes(16), plugin_id=PLUGIN_ID, hostname="deck")
    with pytest.raises(ValueError):
        build_qr_uri(**{**args, **changes})


def test_a_session_uri_is_a_valid_link_for_the_phone():
    uri = make_session().uri
    parsed = parse_uri(uri)
    assert (parsed.host, parsed.port, parsed.name, parsed.plugin_id) == (HOST, PORT, HOSTNAME, PLUGIN_ID)
    assert len(parsed.token) == 16 and len(parsed.secret) == 32 and len(parsed.fingerprint) == 16


# draw order and ids

def test_draw_order_and_device_id_redraw_while_taken():
    taken = b"\x09" * 16
    random = scripted(b"\x01" * 32, b"\x02" * 16, b"\x03" * 32, b"\x04" * 16, taken, taken, b"\x0a" * 16)
    session = make_session(random)
    assert len(random.left) == 4
    phone = make_phone(session)
    status, response = session.pair(dump(phone.pair_request()), T0 + 1, {taken, b"\x77" * 16})
    assert status == 200
    assert response["deviceId"] == (b"\x0a" * 16).hex()
    assert response["pluginNonce"] == (b"\x04" * 16).hex()
    assert random.left == []


# the pair endpoint, check by check

def good_request() -> dict:
    phone = make_phone(make_session(Rand()))
    return phone.pair_request()


def with_changes(**changes) -> bytes:
    return dump({**good_request(), **changes})


def padded(size: int) -> bytes:
    body = dump(good_request())
    return body + b" " * (size - len(body))


BAD_PAIR_BODIES = {
    "one byte over the limit": padded(c.PAIR_BODY_MAX + 1),
    "extra field": with_changes(extra="x"),
    "missing token": dump({k: v for k, v in good_request().items() if k != "token"}),
    "missing name": dump({k: v for k, v in good_request().items() if k != "name"}),
    "upper case token": with_changes(token="AB" * 16),
    "upper case public": with_changes(phonePublic="AB" * 32),
    "upper case nonce": with_changes(phoneNonce="AB" * 16),
    "short token": with_changes(token="ab" * 15),
    "long token": with_changes(token="ab" * 17),
    "short public": with_changes(phonePublic="ab" * 31),
    "short nonce": with_changes(phoneNonce="ab" * 15),
    "non-hex token": with_changes(token="zz" * 16),
    "token is a number": with_changes(token=5),
    "token is a bool": with_changes(token=True),
    "token is null": with_changes(token=None),
    "public is a list": with_changes(phonePublic=["ab" * 32]),
    "name is a number": with_changes(name=5),
    "name is a bool": with_changes(name=True),
    "name is null": with_changes(name=None),
    "empty name": with_changes(name=""),
    "name with NUL": with_changes(name="a\x00b"),
    "name with newline": with_changes(name="a\nb"),
    "name with tab": with_changes(name="a\tb"),
    "name with DEL": with_changes(name="a\x7fb"),
    "name with C1 control": with_changes(name="a\x85b"),
    "name of 65 bytes": with_changes(name="a" * 65),
    "name of 65 bytes, multibyte": with_changes(name="é" * 32 + "a"),
    "name with lone surrogate": with_changes(name="a\ud800b"),
    "not an object": dump([good_request()]),
    "string": dump("text"),
    "number": b"5",
    "null": b"null",
    "not json": b"token=abc",
    "empty": b"",
    "invalid utf-8": b'{"name": "\xff"}',
    "duplicate key": b'{"token": "' + b"ab" * 16 + b'", ' + dump(good_request())[1:],
    "oversize": dump(good_request()) + b" " * c.PAIR_BODY_MAX,
}


@pytest.mark.parametrize("body", BAD_PAIR_BODIES.values(), ids=BAD_PAIR_BODIES.keys())
def test_bad_pair_body_is_bad_message_and_counts_one_failure(body):
    session = make_session()
    assert session.pair(body, T0 + 1, set()) == expired("bad_message", 400)
    assert session.is_active(T0 + 1)
    # the token is untouched, so a good request still works
    assert session.pair(dump(make_phone(session).pair_request()), T0 + 2, set())[0] == 200


def test_pair_bodies_at_the_size_and_name_limits_are_accepted():
    for changes in (dict(name="a" * 64), dict(name="é" * 32), dict(name="📱 ok")):
        session = make_session()
        request = {**make_phone(session).pair_request(), **changes}
        assert session.pair(dump(request), T0 + 1, set())[0] == 200
    session = make_session()
    exact = padded(c.PAIR_BODY_MAX)
    assert len(exact) == c.PAIR_BODY_MAX
    assert session.pair(exact, T0 + 1, set())[0] == 200


def test_pair_body_may_use_any_valid_json_form():
    session = make_session()
    request = make_phone(session).pair_request()
    text = json.dumps(request, indent=2, sort_keys=True, ensure_ascii=False).replace("Test", "\\u0054est")
    assert session.pair(text.encode(), T0 + 1, set())[0] == 200


def test_five_failures_end_the_session_and_the_sixth_valid_attempt_is_refused():
    session = make_session()
    good = dump(make_phone(session).pair_request())
    wrong = dump({**make_phone(session).pair_request(), "token": "ee" * 16})
    for attempt in range(1, 6):
        assert session.pair(wrong, T0 + attempt, set()) == expired("token_invalid", 401)
        assert session.is_active(T0 + attempt) == (attempt < 5)
    assert session.pair(good, T0 + 6, set()) == expired("pair_expired", 410)
    assert session.expires_in_s(T0 + 6) == 0
    assert session.uri == "" and not session.succeeded


def test_bad_bodies_and_wrong_tokens_count_together():
    session = make_session()
    wrong = dump({**make_phone(session).pair_request(), "token": "ee" * 16})
    for body in (wrong, b"x", wrong, b"[]"):
        session.pair(body, T0 + 1, set())
    assert session.is_active(T0 + 1)
    assert session.pair(b"x", T0 + 1, set()) == expired("bad_message", 400)
    assert not session.is_active(T0 + 1)


def test_pair_expired_answers_do_not_count_as_failures():
    session, phone, confirm = paired()
    repeat = dump(phone.pair_request())
    for _ in range(10):
        assert session.pair(repeat, T0 + 2, set()) == expired("pair_expired", 410)
    assert session.is_active(T0 + 2)
    assert session.confirm(confirm, T0 + 3, lambda device: None)[0] == 200


def test_wrong_token_is_token_invalid_and_does_not_spend_the_token():
    session = make_session()
    phone = make_phone(session)
    assert session.pair(dump({**phone.pair_request(), "token": "ee" * 16}), T0 + 1, set()) == expired("token_invalid", 401)
    assert session.pair(dump(phone.pair_request()), T0 + 2, set())[0] == 200


def test_body_is_judged_before_the_session_state():
    session = make_session()
    session.end()
    assert session.pair(b"garbage", T0 + 1, set()) == expired("bad_message", 400)
    assert session.pair(dump(good_request()), T0 + 1, set()) == expired("pair_expired", 410)
    assert reject_without_session(b"garbage") == expired("bad_message", 400)
    assert reject_without_session(dump(good_request())) == expired("pair_expired", 410)


def test_confirm_without_a_session_is_pair_expired():
    assert reject_confirm_without_session(dump({"deviceId": "ab" * 16, "confirm": "cd" * 32})) == expired("pair_expired", 410)
    assert reject_confirm_without_session(b"{}") == expired("bad_message", 400)


def test_qr_deadline_boundary():
    for now_s, active in ((T0 + 119.999, True), (T0 + 120.0, False), (T0 + 500, False)):
        session = make_session()
        assert session.is_active(now_s) is active
    session = make_session()
    assert session.pair(dump(make_phone(session).pair_request()), T0 + 120, set()) == expired("pair_expired", 410)
    session = make_session()
    assert session.pair(dump(make_phone(session).pair_request()), T0 + 119.999, set())[0] == 200


def test_a_timed_out_session_wipes_itself_when_asked():
    session = make_session()
    before = (session._token, session._secret, session._private)
    assert not session.is_active(T0 + 121)
    assert session.uri == ""
    assert not any(value in before for value in vars(session).values())


def test_expires_in_follows_whichever_deadline_applies():
    session = make_session()
    assert session.expires_in_s(T0) == 120
    assert session.expires_in_s(T0 + 100) == 20
    assert session.expires_in_s(T0 + 120) == 0
    session = make_session()
    phone = make_phone(session)
    assert session.pair(dump(phone.pair_request()), T0 + 100, set())[0] == 200
    assert session.expires_in_s(T0 + 100) == 30
    assert session.expires_in_s(T0 + 110) == 20
    assert session.expires_in_s(T0 + 130) == 0 and not session.is_active(T0 + 130)


def test_the_confirm_window_may_outlast_the_qr_deadline():
    session, _, confirm = paired(now_s=T0 + 119)
    assert session.is_active(T0 + 140)
    assert session.confirm(confirm, T0 + 148.9, lambda device: None)[0] == 200


def test_token_cannot_be_reused_after_success():
    session, phone, confirm = paired()
    assert session.confirm(confirm, T0 + 2, lambda device: None)[0] == 200
    assert session.pair(dump(phone.pair_request()), T0 + 3, set()) == expired("pair_expired", 410)


def test_token_is_spent_even_when_a_later_step_fails():
    # a confirm for another device id does not end the session, but the token stays spent
    session, phone, _ = paired()
    wrong_id = dump({"deviceId": "00" * 16, "confirm": "00" * 32})
    assert session.confirm(wrong_id, T0 + 2, lambda device: None) == expired("pair_expired", 410)
    assert session.is_active(T0 + 2)
    assert session.pair(dump(phone.pair_request()), T0 + 3, set()) == expired("pair_expired", 410)


def test_low_order_phone_key_spends_the_token_and_ends_the_session():
    session = make_session()
    request = {**make_phone(session).pair_request(), "phonePublic": "00" * 32}
    assert session.pair(dump(request), T0 + 1, set()) == expired("bad_message", 400)
    assert not session.is_active(T0 + 1) and session.uri == ""
    assert session.pair(dump(make_phone(make_session(Rand())).pair_request()), T0 + 2, set())[0] == 410


def test_pair_response_fields():
    session = make_session()
    status, response = session.pair(dump(make_phone(session).pair_request()), T0 + 1, set())
    assert status == 200 and set(response) == {"pluginPublic", "pluginNonce", "deviceId"}
    assert [len(response[k]) for k in ("pluginPublic", "pluginNonce", "deviceId")] == [64, 32, 32]


# the confirm endpoint, check by check

BAD_CONFIRM_BODIES = {
    "extra field": {"deviceId": "ab" * 16, "confirm": "cd" * 32, "x": 1},
    "missing confirm": {"deviceId": "ab" * 16},
    "upper case id": {"deviceId": "AB" * 16, "confirm": "cd" * 32},
    "upper case confirm": {"deviceId": "ab" * 16, "confirm": "CD" * 32},
    "short id": {"deviceId": "ab" * 15, "confirm": "cd" * 32},
    "short confirm": {"deviceId": "ab" * 16, "confirm": "cd" * 31},
    "id is a number": {"deviceId": 5, "confirm": "cd" * 32},
    "confirm is a bool": {"deviceId": "ab" * 16, "confirm": True},
    "not an object": [1],
}


@pytest.mark.parametrize("body", BAD_CONFIRM_BODIES.values(), ids=BAD_CONFIRM_BODIES.keys())
def test_bad_confirm_body_is_bad_message_and_changes_nothing(body):
    session, _, confirm = paired()
    assert session.confirm(dump(body), T0 + 2, lambda device: pytest.fail("committed")) == expired("bad_message", 400)
    assert session.is_active(T0 + 2)
    assert session.confirm(confirm, T0 + 3, lambda device: None)[0] == 200


def test_oversize_confirm_body_is_bad_message():
    session, _, confirm = paired()
    assert session.confirm(confirm + b" " * 1024, T0 + 2, lambda device: None) == expired("bad_message", 400)


def test_confirm_before_any_pair_request_is_pair_expired():
    session = make_session()
    body = dump({"deviceId": "ab" * 16, "confirm": "cd" * 32})
    assert session.confirm(body, T0 + 1, lambda device: pytest.fail("committed")) == expired("pair_expired", 410)
    assert session.is_active(T0 + 1)


def test_confirm_with_another_device_id_is_pair_expired_and_the_session_survives():
    session, _, confirm = paired()
    other = dump({"deviceId": "00" * 16, "confirm": json.loads(confirm)["confirm"]})
    assert session.confirm(other, T0 + 2, lambda device: pytest.fail("committed")) == expired("pair_expired", 410)
    assert session.confirm(confirm, T0 + 3, lambda device: None)[0] == 200


def test_confirm_after_the_deadline_is_pair_expired_and_ends_the_session():
    session, _, confirm = paired(now_s=T0 + 10)
    assert session.confirm(confirm, T0 + 39.999, lambda device: None)[0] == 200
    session, _, confirm = paired(now_s=T0 + 10)
    assert session.confirm(confirm, T0 + 40.0, lambda device: pytest.fail("committed")) == expired("pair_expired", 410)
    assert not session.is_active(T0 + 40) and not session.succeeded


def test_wrong_confirm_value_ends_the_session_without_committing():
    session, _, confirm = paired()
    tampered = json.loads(confirm)
    tampered["confirm"] = ("00" if tampered["confirm"][:2] != "00" else "01") + tampered["confirm"][2:]
    assert session.confirm(dump(tampered), T0 + 2, lambda device: pytest.fail("committed")) == expired("confirm_failed", 401)
    assert not session.is_active(T0 + 2) and not session.succeeded and session.uri == ""
    assert session.confirm(confirm, T0 + 3, lambda device: pytest.fail("committed")) == expired("pair_expired", 410)


def test_store_failure_is_internal_and_ends_the_session():
    session, _, confirm = paired()

    def failing(device):
        raise StoreError("disk full")

    assert session.confirm(confirm, T0 + 2, failing) == expired("internal", 500)
    assert not session.is_active(T0 + 2) and not session.succeeded
    assert session.confirm(confirm, T0 + 3, lambda device: pytest.fail("committed")) == expired("pair_expired", 410)


def test_success_commits_exactly_one_device_and_a_second_confirm_is_refused():
    session, phone, confirm = paired()
    committed: list[Device] = []
    status, response = session.confirm(confirm, T0 + 2, committed.append)
    assert status == 200
    phone.verify_confirm(response)
    assert len(committed) == 1
    device = committed[0]
    assert (device.key, device.device_id, device.name, device.created_at) == (
        phone.device_key,
        phone.device_id,
        "Test iPhone",
        int(WALL),
    )
    assert session.succeeded and not session.is_active(T0 + 2) and session.uri == ""
    assert session.confirm(confirm, T0 + 3, committed.append) == expired("pair_expired", 410)
    assert len(committed) == 1


def test_success_with_a_real_store(tmp_path):
    store = DeviceStore(tmp_path / "devices.json")
    session = make_session()
    phone = make_phone(session)
    _, response = session.pair(dump(phone.pair_request()), T0 + 1, {d.device_id for d in store.devices()})
    status, answer = session.confirm(dump(phone.on_pair_response(response)), T0 + 2, store.add)
    assert status == 200
    phone.verify_confirm(answer)
    assert DeviceStore(tmp_path / "devices.json").get(phone.device_id).key == phone.device_key


def test_failed_pairing_leaves_the_store_empty(tmp_path):
    store = DeviceStore(tmp_path / "devices.json")
    session, _, _ = paired()
    session.confirm(dump({"deviceId": "ab" * 16, "confirm": "cd" * 32}), T0 + 2, store.add)
    assert store.devices() == []


def test_end_is_idempotent_and_drops_every_secret():
    session, phone, _ = paired()
    held = (session._token, session._secret, session._private, session._pending.device_key)
    session.end()
    session.end()
    assert session._pending is None
    assert not any(value in held for value in vars(session).values())
    assert not session.is_active(T0 + 1) and session.expires_in_s(T0 + 1) == 0


def test_reprs_hide_every_secret_and_the_phone_name():
    session, phone, _ = paired()
    text = repr(session) + repr(session._pending)
    held = (session._token, session._secret, session._private, phone.device_key, session._pending.confirm_plugin)
    assert not any(secret.hex() in text or repr(secret) in text for secret in held)
    assert "Test iPhone" not in text


def test_secrets_are_compared_in_constant_time(monkeypatch):
    calls = []
    real = pairing.hmac.compare_digest
    monkeypatch.setattr(pairing.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))
    session = make_session()
    phone = make_phone(session)
    _, response = session.pair(dump(phone.pair_request()), T0 + 1, set())
    confirm = phone.on_pair_response(response)
    session.confirm(dump(confirm), T0 + 2, lambda device: None)
    assert (phone.uri.token, phone.uri.token) in calls
    assert (bytes.fromhex(confirm["confirm"]),) * 2 in calls
    assert (phone.device_id, phone.device_id) in calls


# the test phone itself

def full_pairing_with_os_randomness():
    session = PairingSession(plugin_id=PLUGIN_ID, host=HOST, port=PORT, hostname=HOSTNAME, now_s=T0)
    phone = PhonePairing(session.uri, "Phone", b"\x07" * 32, b"\x08" * 16)
    return session, phone


def test_end_to_end_with_os_randomness():
    session, phone = full_pairing_with_os_randomness()
    committed = []
    _, response = session.pair(dump(phone.pair_request()), T0 + 1, set())
    _, answer = session.confirm(dump(phone.on_pair_response(response)), T0 + 2, committed.append)
    phone.verify_confirm(answer)
    assert committed[0].key == phone.device_key and len(phone.device_key) == 32


def test_phone_refuses_a_wrong_plugin_confirmation_and_forgets_the_key():
    session, phone = full_pairing_with_os_randomness()
    _, response = session.pair(dump(phone.pair_request()), T0 + 1, set())
    phone.on_pair_response(response)
    with pytest.raises(PairingFailure, match="confirmation"):
        phone.verify_confirm({"confirm": "00" * 32})
    assert phone.device_key is None and phone.device_id is None


def test_phone_refuses_a_swapped_public_key():
    session, phone = full_pairing_with_os_randomness()
    _, response = session.pair(dump(phone.pair_request()), T0 + 1, set())
    other = PhonePairing(session.uri, "x", b"\x09" * 32, bytes(16)).public
    with pytest.raises(PairingFailure, match="fingerprint"):
        phone.on_pair_response({**response, "pluginPublic": other.hex()})


@pytest.mark.parametrize("response", [{}, {"pluginPublic": "00" * 32}, {"pluginPublic": "AB" * 32, "pluginNonce": "00" * 16, "deviceId": "00" * 16}])
def test_phone_refuses_a_malformed_pair_response(response):
    _, phone = full_pairing_with_os_randomness()
    with pytest.raises(PairingFailure):
        phone.on_pair_response(response)


GOOD_URI = "hotbar://pair?v=1&host=10.0.0.2&port=5000&token=" + "01" * 16 + "&secret=" + "02" * 32 + "&fp=" + "03" * 16 + "&pid=" + "04" * 16 + "&name=deck"


@pytest.mark.parametrize(
    "uri",
    [
        GOOD_URI.replace("hotbar://", "https://"),
        GOOD_URI.replace("pair?", "pairing?"),
        GOOD_URI.replace("v=1&", ""),
        GOOD_URI + "&extra=1",
        GOOD_URI + "&name=again",
        GOOD_URI.replace("v=1&host=10.0.0.2", "host=10.0.0.2&v=1"),
        GOOD_URI.replace("v=1", "v=2"),
        GOOD_URI.replace("10.0.0.2", "deck.local"),
        GOOD_URI.replace("port=5000", "port=0"),
        GOOD_URI.replace("port=5000", "port=65536"),
        GOOD_URI.replace("port=5000", "port=50x"),
        GOOD_URI.replace("01" * 16, "AB" * 16),
        GOOD_URI.replace("02" * 32, "02" * 31),
        GOOD_URI.replace("&name=deck", "&name="),
        GOOD_URI.replace("&name=deck", "&name=" + "a" * 64),
        GOOD_URI.replace("&name=deck", "&name=de%zz"),
        GOOD_URI.replace("&name=deck", "&name=de%C3"),
        GOOD_URI.replace("&name=deck", "&name=de ck"),
        GOOD_URI.replace("&name=deck", "&name"),
    ],
)
def test_phone_refuses_a_malformed_link(uri):
    with pytest.raises(PairingFailure):
        parse_uri(uri)


def test_phone_accepts_either_case_in_percent_escapes():
    assert parse_uri(GOOD_URI.replace("&name=deck", "&name=%c3%a9%C3%A9")).name == "éé"
