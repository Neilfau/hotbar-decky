# End-to-end tests: a real server on loopback, driven by a test phone over HTTP and WebSocket.
import asyncio
import contextlib
import functools
import json
import logging
import os
import socket
from pathlib import Path

import aiohttp
import pytest
from aiohttp import WSMsgType

from hotbar import constants as c
from hotbar import server as server_module
from hotbar.input.device import EV_KEY, EV_REL, EV_SYN, FakeDevice
from hotbar.input.injector import Injector
from hotbar.messages import truncate_utf8
from hotbar.netutil import AddressThrottle, default_local_ip, is_allowed_source
from hotbar.server import QUEUE_MAX, HotBarServer
from hotbar.store import DeviceStore, StoreError
from phone_client import PhonePairing, Sender, encode, parse_uri, phone_receive

HOSTNAME = "deck-test"
TEST_TIMEOUT_S = 30
CLOSED = (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR)

SYN = (EV_SYN, 0, 0)
KEY_A, KEY_B, KEY_ENTER, KEY_F1, LCTRL, LSHIFT = 30, 48, 28, 59, 29, 42
BTN_LEFT, BTN_RIGHT = 0x110, 0x111


def down(code):
    return (EV_KEY, code, 1)


def up(code):
    return (EV_KEY, code, 0)


def tap(code, mods=()):
    """Events of one key press, with its modifiers held around it."""
    events = [*(down(m) for m in mods), SYN] if mods else []
    events += [down(code), SYN, up(code), SYN]
    return events + ([*(up(m) for m in reversed(mods)), SYN] if mods else [])


def keys(*taps):
    return [event for t in taps for event in t]


def run(test):
    """Runs an async test body under asyncio.run, with a timeout so a hang fails instead of stalling."""

    @functools.wraps(test)
    def wrapper(*args, **kwargs):
        asyncio.run(asyncio.wait_for(test(*args, **kwargs), TEST_TIMEOUT_S))

    return wrapper


async def instant_sleep(_seconds):
    await asyncio.sleep(0)


async def short_sleep(_seconds):
    await asyncio.sleep(0.002)


def gated_sleep():
    """A sleep that never finishes, so an action stays in flight until it is cancelled."""
    gate = asyncio.Event()

    async def sleep(_seconds):
        await gate.wait()

    return sleep


async def until(condition, timeout=3.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "condition not reached in time"
        await asyncio.sleep(0.005)


class Clock:
    def __init__(self):
        self.now = 1_000_000
        self.step = 0  # added after every reading, to space messages the server judges back to back

    def __call__(self):
        reading = self.now
        self.now += self.step
        return reading

    def advance(self, ms):
        self.now += ms


class _Collect(logging.Handler):
    def __init__(self, sink):
        super().__init__(logging.DEBUG)
        self.sink = sink

    def emit(self, record):
        self.sink.append(record)


class Rig:
    def url(self, path, scheme="http"):
        return f"{scheme}://127.0.0.1:{self.server.port}{path}"


@contextlib.asynccontextmanager
async def make_rig(tmp_path, *, sleep=instant_sleep, store_port=None, start=True, **server_kwargs):
    rig = Rig()
    rig.clock = Clock()
    rig.path = tmp_path / "devices.json"
    rig.store = DeviceStore(rig.path)
    if store_port is not None:
        rig.store.set_port(store_port)
    rig.kb, rig.pointer = FakeDevice(), FakeDevice()
    rig.injector = Injector(rig.kb, rig.pointer, sleep)
    rig.records = []
    rig.changes = 0
    rig.snapshots = []
    logger = logging.getLogger(f"hotbar.test.{id(rig)}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(_Collect(rig.records))

    def changed():
        rig.changes += 1
        rig.snapshots.append(rig.server.state())

    kwargs = {
        "store": rig.store,
        "injector": rig.injector,
        "logger": logger,
        "hostname": HOSTNAME,
        "local_ip": lambda: "127.0.0.1",
        "on_change": changed,
        "port": 0,
        "bind_host": "127.0.0.1",
        "clock_ms": rig.clock,
    }
    kwargs.update(server_kwargs)
    rig.server = HotBarServer(**kwargs)
    if start:
        await rig.server.start()
    rig.http = aiohttp.ClientSession()
    rig.phones = []
    try:
        yield rig
    finally:
        for phone in rig.phones:
            await phone.close()
        await rig.http.close()
        await rig.server.stop()


class Paired:
    def __init__(self, device_id, key, name):
        self.device_id, self.key, self.name = device_id, key, name


async def pair(rig, name="Test Phone"):
    uri = rig.server.start_pairing()["pairing"]["uri"]
    phone = PhonePairing(uri, name, os.urandom(32), os.urandom(16))
    async with rig.http.post(rig.url("/v1/pair"), json=phone.pair_request()) as response:
        assert response.status == 200
        confirm = phone.on_pair_response(await response.json())
    async with rig.http.post(rig.url("/v1/pair/confirm"), json=confirm) as response:
        assert response.status == 200
        phone.verify_confirm(await response.json())
    return Paired(phone.device_id, phone.device_key, name)


class PhoneBase:
    """What both channels share: the expected shape of each answer to the last message sent."""

    def __init__(self, rig, paired):
        self.rig, self.paired = rig, paired
        self.sender = None
        self.counter = None
        self.last_wire = None
        rig.phones.append(self)

    async def close(self):
        pass

    def ok(self):
        return {"type": "ok", "sender": self.sender.sender_id.hex(), "counter": self.counter}

    def error(self, code, **extra):
        return {"type": "error", "sender": self.sender.sender_id.hex(), "counter": self.counter, "error": code, **extra}

    def welcome(self):
        return {
            "type": "welcome",
            "sender": self.sender.sender_id.hex(),
            "counter": self.counter,
            "pluginId": self.rig.store.plugin_id.hex(),
            "maxVersion": 1,
            "hostname": HOSTNAME,
        }

    def _open(self, wire):
        outstanding = {(self.sender.sender_id, self.counter)}
        received = phone_receive(wire, self.paired.device_id, self.paired.key, outstanding)
        assert received.accepted, received.reason
        return received.response


class HttpPhone(PhoneBase):
    """Every command is its own request with its own sender and challenge, as a widget would send it."""

    kind = "http"

    async def get_challenge(self):
        async with self.rig.http.post(self.rig.url("/v1/challenge")) as response:
            assert response.status == 200
            assert response.content_type == "application/json"
            body = await response.json()
        assert set(body) == {"challenge", "ttlMs"} and body["ttlMs"] == c.CHALLENGE_TTL_MS
        return body["challenge"]

    async def plain(self, wire):
        async with self.rig.http.post(self.rig.url("/v1/cmd"), data=wire) as response:
            assert response.content_type == "application/json"
            return response.status, await response.json()

    async def _post(self, wire):
        async with self.rig.http.post(self.rig.url("/v1/cmd"), data=wire) as response:
            data = await response.read()
            return response.status, response.content_type, data

    async def ask(self, body, *, challenge=True, counter=None, keep_sender=False):
        if not keep_sender or self.sender is None:
            self.sender = Sender(self.paired.device_id, self.paired.key)
        if counter is not None:
            self.sender.counter = counter
        if challenge is True:
            challenge = None if keep_sender else await self.get_challenge()
        if challenge:
            body = {**body, "challenge": challenge}
        self.counter = self.sender.counter
        self.last_wire = self.sender.seal(body)
        return await self.replay()

    async def replay(self):
        status, content_type, data = await self._post(self.last_wire)
        assert (status, content_type) == (200, "application/octet-stream"), (status, data)
        return self._open(data)

    send = ask


class StreamPhone(PhoneBase):
    """One WebSocket and one sender for the whole connection."""

    kind = "stream"

    @classmethod
    async def connect(cls, rig, paired, autoping=True):
        phone = cls(rig, paired)
        phone.ws = await rig.http.ws_connect(rig.url("/v1/ws", "ws"), autoping=autoping)
        phone.frames = asyncio.Queue()
        phone.pump = asyncio.create_task(phone._pump())
        first = await phone.text()
        assert first["type"] == "challenge" and first["ttlMs"] == c.CHALLENGE_TTL_MS
        assert set(first) == {"type", "challenge", "ttlMs"}
        phone.challenge = first["challenge"]
        phone.sender = Sender(paired.device_id, paired.key)
        phone.registered = False
        return phone

    async def _pump(self):
        while True:
            msg = await self.ws.receive()
            self.frames.put_nowait(msg)
            if msg.type in CLOSED:
                return

    async def close(self):
        self.pump.cancel()
        await self.ws.close()

    async def frame(self, timeout=3.0):
        return await asyncio.wait_for(self.frames.get(), timeout)

    async def text(self):
        msg = await self.frame()
        assert msg.type is WSMsgType.TEXT, msg
        return json.loads(msg.data)

    async def get_challenge(self):
        await self.ws.send_str('{"type":"challenge"}')
        frame = await self.text()
        assert frame["type"] == "challenge"
        return frame["challenge"]

    async def plain(self, wire):
        await self.ws.send_bytes(wire)
        return None, await self.text()

    async def send(self, body, *, challenge=True, counter=None, keep_sender=True):
        if counter is not None:
            self.sender.counter = counter
        if challenge is True:
            challenge = None if self.registered else self.challenge
        if challenge:
            body = {**body, "challenge": challenge}
        self.registered = True
        self.counter = self.sender.counter
        self.last_wire = self.sender.seal(body)
        await self.ws.send_bytes(self.last_wire)

    async def reply(self):
        msg = await self.frame()
        assert msg.type is WSMsgType.BINARY, msg
        return self._open(msg.data)

    async def ask(self, body, **kwargs):
        await self.send(body, **kwargs)
        return await self.reply()

    async def replay(self):
        await self.ws.send_bytes(self.last_wire)
        return await self.reply()

    async def closed(self, timeout=3.0):
        """Everything the server sent up to and including its close."""
        seen = []
        while True:
            msg = await self.frame(timeout)
            seen.append(msg)
            if msg.type in CLOSED:
                return seen


async def open_phone(channel, rig, paired):
    if channel == "http":
        return HttpPhone(rig, paired)
    return await StreamPhone.connect(rig, paired)


CHANNELS = ["http", "stream"]
HELLO = {"type": "hello"}


# Pairing and messages

@run
async def test_pairing_over_http_stores_the_device(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig, "Alice's Phone")
        assert rig.store.get(paired.device_id).key == paired.key
        assert rig.server.state() == {
            "listening": True,
            "error": None,
            "devices": [
                {
                    "deviceId": paired.device_id.hex(),
                    "name": "Alice's Phone",
                    "createdAt": rig.store.get(paired.device_id).created_at,
                    "connected": False,
                }
            ],
            "pairing": None,
        }
        assert paired.key.hex() in rig.path.read_text()


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_hello_is_answered_with_welcome(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        assert await phone.ask(HELLO) == phone.welcome()


@run
async def test_welcome_cuts_a_long_hostname_to_its_byte_limit(tmp_path):
    long_name = "é" * 70
    async with make_rig(tmp_path, hostname=long_name) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        answer = await phone.ask(HELLO)
        assert answer["hostname"] == truncate_utf8(long_name, c.HOSTNAME_MAX_BYTES) == "é" * 31


ACTIONS = [
    # name, body, keyboard events, pointer events, answered on the stream
    ("press", {"type": "press", "key": 4, "mods": 1}, keys(tap(KEY_A, [LCTRL])), [], True),
    ("press without modifiers", {"type": "press", "key": 5, "mods": 0}, keys(tap(KEY_B)), [], True),
    (
        "type",
        {"type": "type", "text": "aB"},
        keys(tap(KEY_A), tap(KEY_B, [LSHIFT])),
        [],
        True,
    ),
    (
        "type with open and submit",
        {"type": "type", "text": "a", "open": {"key": 58, "mods": 0}, "submit": True},
        keys(tap(KEY_F1), tap(KEY_A), tap(KEY_ENTER)),
        [],
        True,
    ),
    ("move", {"type": "move", "dx": 5, "dy": -3}, [], [(EV_REL, 0x00, 5), (EV_REL, 0x01, -3), SYN], False),
    ("button down", {"type": "button", "button": "left", "state": "down"}, [], [down(BTN_LEFT), SYN], False),
    ("button up", {"type": "button", "button": "right", "state": "up"}, [], [up(BTN_RIGHT), SYN], False),
    (
        "scroll",
        {"type": "scroll", "dx": 0, "dy": 120},
        [],
        [(EV_REL, 0x0B, 120), (EV_REL, 0x08, 1), SYN],
        False,
    ),
]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("body, kb, pointer, answered", [a[1:] for a in ACTIONS], ids=[a[0] for a in ACTIONS])
@run
async def test_action_injects_exactly_its_events(tmp_path, channel, body, kb, pointer, answered):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        if channel == "stream" and not answered:
            # No answer is sent for pointer events, so the next frame belongs to the message after it.
            await phone.send(body)
            assert await phone.ask(HELLO) == phone.welcome()
        else:
            assert await phone.ask(body) == phone.ok()
        assert rig.kb.events == kb
        assert rig.pointer.events == pointer


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_unpair_answers_ok_then_revokes_the_device(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        phone = await open_phone(channel, rig, paired)
        assert await phone.ask({"type": "unpair"}) == phone.ok()
        # The device is already gone when the phone sees the ok.
        assert rig.store.get(paired.device_id) is None
        assert rig.server.state()["devices"] == []
        assert paired.key.hex() not in rig.path.read_text()
        if channel == "stream":
            assert (await phone.closed())[-1].type in CLOSED
        status, body = await HttpPhone(rig, paired).plain(Sender(paired.device_id, paired.key).seal(HELLO))
        assert (status, body) == (401, {"error": "unknown_device"})


@run
async def test_commands_queued_behind_an_unpair_never_reach_the_injector(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        phone = await StreamPhone.connect(rig, paired)
        rig.clock.step = 150  # past the press and type gap between any two frames
        # Nothing here yields until every frame is sent, so the server has all of them queued
        # before its worker starts on the unpair.
        await phone.send({"type": "unpair"})
        unpair_counter = phone.counter
        for body in (
            {"type": "press", "key": 4, "mods": 0},
            {"type": "type", "text": "ab"},
            {"type": "press", "key": 5, "mods": 0},
            {"type": "move", "dx": 5, "dy": 5},
            {"type": "button", "button": "left", "state": "down"},
        ):
            await phone.send(body)

        seen = await phone.closed()

        phone.counter = unpair_counter
        assert phone._open(seen[0].data) == phone.ok()
        assert seen[0].type is WSMsgType.BINARY and seen[-1].type in CLOSED
        assert phone.ws.close_code == 1001
        assert rig.kb.events == [] and rig.pointer.events == []
        assert rig.store.get(paired.device_id) is None
        assert paired.key.hex() not in rig.path.read_text()


# Plaintext errors

def _sealed_by(paired, body=HELLO):
    return Sender(paired.device_id, paired.key).seal(body)


def _tampered(paired):
    wire = bytearray(_sealed_by(paired))
    wire[-1] ^= 1
    return bytes(wire)


PLAIN_CASES = [
    ("too short", lambda p: b"\x01" * 10, 400, "bad_message", {}),
    ("version 0", lambda p: bytes([0, 1]) + bytes(64), 400, "bad_message", {}),
    ("newer version", lambda p: bytes([2, 1]) + bytes(64), 426, "version_too_new", {"maxVersion": 1}),
    ("wrong direction", lambda p: bytes([1, 2]) + bytes(64), 400, "bad_direction", {}),
    (
        "unknown device",
        lambda p: Sender(os.urandom(16), os.urandom(32)).seal(HELLO),
        401,
        "unknown_device",
        {},
    ),
    ("tampered tag", _tampered, 401, "auth_failed", {}),
]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("make_wire, status, code, extra", [p[1:] for p in PLAIN_CASES], ids=[p[0] for p in PLAIN_CASES])
@run
async def test_plaintext_errors(tmp_path, channel, make_wire, status, code, extra):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        phone = await open_phone(channel, rig, paired)
        got_status, body = await phone.plain(make_wire(paired))
        if channel == "http":
            assert (got_status, body) == (status, {"error": code, **extra})
        else:
            assert body == {"type": "error", "error": code, **extra}
        assert rig.kb.events == [] and rig.pointer.events == []


# Sealed errors

SEALED_CASES = [
    ("bad body", HELLO | {"bogus": 1}, True, "bad_body", {}),
    ("unknown type", {"type": "frobnicate"}, True, "unknown_type", {}),
    ("unsupported key", {"type": "press", "key": 0x66, "mods": 0}, True, "unsupported_key", {}),
    ("modifier as key", {"type": "press", "key": 0xE0, "mods": 0}, True, "unsupported_key", {}),
    ("unsupported character", {"type": "type", "text": "café"}, True, "unsupported_char", {}),
    ("no challenge", HELLO, False, "challenge_required", {}),
    ("unknown challenge", HELLO, "00" * 16, "challenge_invalid", {}),
]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("body, challenge, code, extra", [s[1:] for s in SEALED_CASES], ids=[s[0] for s in SEALED_CASES])
@run
async def test_sealed_errors(tmp_path, channel, body, challenge, code, extra):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        assert await phone.ask(body, challenge=challenge) == phone.error(code, **extra)
        assert rig.kb.events == [] and rig.pointer.events == []


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_expired_challenge(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        challenge = await phone.get_challenge()
        rig.clock.advance(c.CHALLENGE_TTL_MS)
        assert await phone.ask(HELLO, challenge=challenge) == phone.error("challenge_invalid")


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_spent_challenge(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        first, second = await open_phone(channel, rig, paired), await open_phone(channel, rig, paired)
        challenge = await first.get_challenge()
        assert await first.ask(HELLO, challenge=challenge) == first.welcome()
        assert await second.ask(HELLO, challenge=challenge) == second.error("challenge_invalid")


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_replayed_message(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        assert await phone.ask(HELLO) == phone.welcome()
        assert await phone.replay() == phone.error("replayed")


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_counter_too_old(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        assert await phone.ask(HELLO, counter=100) == phone.welcome()
        answer = await phone.ask(HELLO, counter=100 - c.WINDOW_SIZE, challenge=False, keep_sender=True)
        assert answer == phone.error("counter_too_old")


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_press_gap_is_rate_limited_with_retry_hint(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        press = {"type": "press", "key": 4, "mods": 0}
        assert await phone.ask(press) == phone.ok()
        rig.clock.advance(c.GAP_PLUGIN_MS - 40)
        assert await phone.ask(press, challenge=True, keep_sender=True) == phone.error("rate_limited", retryAfterMs=40)
        assert rig.kb.events == keys(tap(KEY_A))
        rig.clock.advance(40)
        assert await phone.ask(press, keep_sender=True) == phone.ok()
        assert rig.kb.events == keys(tap(KEY_A), tap(KEY_A))


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_failing_device_answers_internal_and_recovers(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        rig.kb.fail = True
        press = {"type": "press", "key": 4, "mods": 0}
        assert await phone.ask(press) == phone.error("internal")
        rig.kb.fail = False
        rig.clock.advance(1000)
        assert await phone.ask(press, keep_sender=True) == phone.ok()
        # The failed press may have left the key down, so the next action releases it once more.
        assert rig.kb.events == keys(tap(KEY_A), [up(KEY_A), SYN])


@run
async def test_invalid_type_injects_nothing_and_valid_one_still_runs(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        bad = {"type": "type", "text": "abé"}
        assert await phone.ask(bad) == phone.error("unsupported_char")
        assert rig.kb.events == []
        rig.clock.advance(200)
        assert await phone.ask({"type": "type", "text": "ab"}) == phone.ok()
        assert rig.kb.events == keys(tap(KEY_A), tap(KEY_B))


@run
async def test_type_and_press_from_two_devices_do_not_interleave(tmp_path):
    async with make_rig(tmp_path, sleep=short_sleep) as rig:
        first = await StreamPhone.connect(rig, await pair(rig, "One"))
        second = await StreamPhone.connect(rig, await pair(rig, "Two"))
        await first.send({"type": "type", "text": "abcdef"})
        await until(lambda: rig.kb.events)
        await second.send({"type": "press", "key": 4, "mods": 0})
        assert await first.reply() == first.ok()
        assert await second.reply() == second.ok()
        a_to_f = [30, 48, 46, 32, 18, 33]
        assert rig.kb.events == keys(*(tap(code) for code in a_to_f), tap(KEY_A))


# Pointer events

@run
async def test_pointer_burst_is_dropped_silently_on_the_stream_and_buttons_are_not_limited(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        move = {"type": "move", "dx": 1, "dy": 1}
        for _ in range(c.POINTER_BURST + 10):
            await phone.send(move)
        # The next frame is the answer to this hello, so none of the dropped moves produced a frame.
        assert await phone.ask(HELLO) == phone.welcome()
        assert rig.pointer.events == [(EV_REL, 0, 1), (EV_REL, 1, 1), SYN] * c.POINTER_BURST
        before = len(rig.pointer.events)
        for state in ("down", "up", "down", "up"):
            await phone.send({"type": "button", "button": "left", "state": state})
        assert await phone.ask(HELLO) == phone.welcome()
        assert rig.pointer.events[before:] == [down(BTN_LEFT), SYN, up(BTN_LEFT), SYN] * 2


@run
async def test_pointer_burst_over_http_answers_the_drop_with_a_rate_limit_error(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone("http", rig, await pair(rig))
        move = {"type": "move", "dx": 1, "dy": 1}
        for _ in range(c.POINTER_BURST):
            assert await phone.ask(move) == phone.ok()
        # Empty bucket and a frozen clock: a whole token is 4 ms away at 250 tokens a second.
        assert await phone.ask(move) == phone.error("rate_limited", retryAfterMs=4)
        assert len(rig.pointer.events) == 3 * c.POINTER_BURST
        assert await phone.ask({"type": "button", "button": "left", "state": "down"}) == phone.ok()
        assert rig.pointer.events[-2:] == [down(BTN_LEFT), SYN]


# Revocation

@run
async def test_removing_one_device_leaves_the_other_working(tmp_path):
    async with make_rig(tmp_path) as rig:
        gone, kept = await pair(rig, "Gone"), await pair(rig, "Kept")
        gone_stream = await StreamPhone.connect(rig, gone)
        kept_stream = await StreamPhone.connect(rig, kept)
        assert await gone_stream.ask(HELLO) == gone_stream.welcome()
        assert await kept_stream.ask(HELLO) == kept_stream.welcome()
        assert [d["connected"] for d in rig.server.state()["devices"]] == [True, True]

        state = await rig.server.remove_device(gone.device_id.hex())

        assert [d["deviceId"] for d in state["devices"]] == [kept.device_id.hex()]
        assert (await gone_stream.closed())[-1].type in CLOSED
        assert gone.key.hex() not in rig.path.read_text() and kept.key.hex() in rig.path.read_text()
        wire = _sealed_by(gone)
        assert await HttpPhone(rig, gone).plain(wire) == (401, {"error": "unknown_device"})
        fresh = await StreamPhone.connect(rig, gone)
        assert await fresh.plain(wire) == (None, {"type": "error", "error": "unknown_device"})
        assert await kept_stream.ask({"type": "press", "key": 4, "mods": 0}, keep_sender=True) == kept_stream.ok()
        kept_http = HttpPhone(rig, kept)
        assert await kept_http.ask(HELLO) == kept_http.welcome()


@run
async def test_removal_forgets_the_per_device_receiver_state(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        phone = HttpPhone(rig, paired)
        assert await phone.ask({"type": "press", "key": 4, "mods": 0}) == phone.ok()
        assert await phone.ask({"type": "move", "dx": 1, "dy": 1}, keep_sender=True) == phone.ok()
        receiver = rig.server._receiver
        device = paired.device_id
        assert any(key[0] == device for key in receiver.senders)
        assert device in receiver.last_press_type_ms and device in receiver.buckets

        await rig.server.remove_device(device.hex())

        assert not any(key[0] == device for key in receiver.senders)
        assert device not in receiver.last_press_type_ms and device not in receiver.buckets


@run
async def test_remove_all_devices_revokes_every_connection(tmp_path):
    async with make_rig(tmp_path) as rig:
        phones = [await StreamPhone.connect(rig, await pair(rig, f"P{n}")) for n in range(2)]
        for phone in phones:
            await phone.ask(HELLO)
        state = await rig.server.remove_all_devices()
        assert state["devices"] == []
        for phone in phones:
            assert (await phone.closed())[-1].type in CLOSED
        assert json.loads(rig.path.read_text())["devices"] == []


@run
async def test_removal_with_failing_storage_still_revokes_and_reports(tmp_path, monkeypatch):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)

        def broken(*args):
            raise StoreError("disk")

        monkeypatch.setattr(rig.store, "_write", broken)
        state = await rig.server.remove_device(paired.device_id.hex())
        assert state["devices"] == []
        assert state["error"] == "Key storage failed; a removed key may still be in the file"
        status, body = await HttpPhone(rig, paired).plain(_sealed_by(paired))
        assert (status, body) == (401, {"error": "unknown_device"})


@run
async def test_removing_an_unknown_device_changes_nothing(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        before = rig.changes
        for bad in ("00" * 16, "not hex", ""):
            state = await rig.server.remove_device(bad)
            assert [d["deviceId"] for d in state["devices"]] == [paired.device_id.hex()]
        assert rig.changes == before


# Held buttons

LEFT_DOWN = {"type": "button", "button": "left", "state": "down"}
HELD_AND_RELEASED = [down(BTN_LEFT), SYN, up(BTN_LEFT), SYN]


@run
async def test_button_is_released_when_its_stream_closes(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        await phone.send(LEFT_DOWN)
        assert await phone.ask(HELLO) == phone.welcome()
        assert rig.pointer.events == [down(BTN_LEFT), SYN]
        await phone.ws.close()
        await until(lambda: rig.pointer.events == HELD_AND_RELEASED)


@run
async def test_button_is_released_when_the_device_is_revoked(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        phone = await open_phone("http", rig, paired)
        assert await phone.ask(LEFT_DOWN) == phone.ok()
        await rig.server.remove_device(paired.device_id.hex())
        assert rig.pointer.events == HELD_AND_RELEASED


@pytest.mark.parametrize("channel", CHANNELS)
@run
async def test_button_is_released_on_stop(tmp_path, channel):
    async with make_rig(tmp_path) as rig:
        phone = await open_phone(channel, rig, await pair(rig))
        if channel == "http":
            assert await phone.ask(LEFT_DOWN) == phone.ok()
        else:
            await phone.send(LEFT_DOWN)
            assert await phone.ask(HELLO) == phone.welcome()
        await rig.server.stop()
        assert rig.pointer.events == HELD_AND_RELEASED


@run
async def test_button_of_an_evicted_sender_is_released(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "SENDER_TABLE_MAX", 2)
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        phone = await open_phone("http", rig, paired)
        await phone.ask(LEFT_DOWN)
        await phone.ask(HELLO)
        assert rig.pointer.events == [down(BTN_LEFT), SYN]
        await phone.ask(HELLO)
        await until(lambda: rig.pointer.events == HELD_AND_RELEASED)


@run
async def test_stream_closed_during_a_long_type_leaves_no_key_down(tmp_path):
    async with make_rig(tmp_path, sleep=gated_sleep()) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        await phone.send({"type": "type", "text": "ab"})
        await until(lambda: rig.kb.events == [down(KEY_A), SYN])
        await phone.ws.close()
        await until(lambda: rig.kb.events == [down(KEY_A), SYN, up(KEY_A), SYN])
        await asyncio.sleep(0.05)
        assert rig.kb.events == keys(tap(KEY_A))


@run
async def test_revoking_a_device_cancels_its_http_action_in_flight(tmp_path):
    async with make_rig(tmp_path, sleep=gated_sleep()) as rig:
        paired = await pair(rig)
        request = asyncio.create_task(HttpPhone(rig, paired).ask({"type": "type", "text": "a"}))
        await until(lambda: rig.kb.events == [down(KEY_A), SYN])
        await rig.server.remove_device(paired.device_id.hex())
        with pytest.raises(aiohttp.ClientConnectionError):
            await request
        assert rig.kb.events == keys(tap(KEY_A))


@run
async def test_full_queue_closes_the_socket(tmp_path):
    async with make_rig(tmp_path, sleep=gated_sleep()) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        await phone.send({"type": "type", "text": "a"})
        await until(lambda: rig.kb.events == [down(KEY_A), SYN])
        with contextlib.suppress(ConnectionError):
            for _ in range(QUEUE_MAX + 5):
                await phone.send({"type": "button", "button": "left", "state": "up"})
        closing = (await phone.closed())[-1]
        assert (closing.type, closing.data) == (WSMsgType.CLOSE, 1008)
        await until(lambda: rig.kb.events == keys(tap(KEY_A)))


# Stream rules

@run
async def test_text_frames_other_than_a_challenge_request_get_an_error_frame(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        expected = {"type": "error", "error": "bad_message"}
        for text in ('{"type":"nope"}', "not json", "[]", '{"type":"challenge","extra":1}', '{"type":"challenge"}'.ljust(c.TEXT_FRAME_MAX + 1)):
            await phone.ws.send_str(text)
            assert await phone.text() == expected
        # A request at the size limit is still understood.
        await phone.ws.send_str('{"type":"challenge"}'.ljust(c.TEXT_FRAME_MAX))
        assert (await phone.text())["type"] == "challenge"


@run
async def test_challenge_request_gives_a_new_usable_challenge(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        fresh = await phone.get_challenge()
        assert fresh != phone.challenge
        assert await phone.ask(HELLO, challenge=fresh) == phone.welcome()


@run
async def test_plaintext_error_cap_closes_the_socket(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        for _ in range(c.WS_PLAIN_ERROR_MAX):
            await phone.ws.send_str("nope")
        seen = await phone.closed()
        errors = [m for m in seen if m.type is WSMsgType.TEXT]
        assert len(errors) == c.WS_PLAIN_ERROR_MAX
        assert all(json.loads(m.data) == {"type": "error", "error": "bad_message"} for m in errors)
        assert seen[-1].type is WSMsgType.CLOSE


@run
async def test_idle_socket_is_closed_after_the_auth_timeout(tmp_path):
    async with make_rig(tmp_path, auth_timeout_s=0.2) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        assert (await phone.closed())[-1].type is WSMsgType.CLOSE


@run
async def test_socket_with_an_authentic_message_survives_the_auth_timeout(tmp_path):
    async with make_rig(tmp_path, auth_timeout_s=0.2) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        assert await phone.ask(HELLO) == phone.welcome()
        await asyncio.sleep(0.5)
        assert await phone.ask(HELLO) == phone.welcome()


@run
async def test_sealed_error_counts_as_authentic(tmp_path):
    async with make_rig(tmp_path, auth_timeout_s=0.2) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        assert await phone.ask({"type": "frobnicate"}) == phone.error("unknown_type")
        await asyncio.sleep(0.5)
        assert not phone.ws.closed


@run
async def test_oversize_binary_frame_closes_the_socket(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        await phone.ws.send_bytes(bytes(c.MAX_ENVELOPE_LEN + 1))
        closing = (await phone.closed())[-1]
        assert (closing.type, closing.data) == (WSMsgType.CLOSE, 1009)


@run
async def test_unanswered_pings_close_the_socket_after_two(tmp_path):
    async with make_rig(tmp_path, ping_interval_s=0.1) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig), autoping=False)
        seen = await phone.closed()
        assert [m.type for m in seen].count(WSMsgType.PING) == 2
        assert seen[-1].type is WSMsgType.CLOSE


@run
async def test_socket_that_answers_pings_stays_open(tmp_path):
    async with make_rig(tmp_path, ping_interval_s=0.05) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        await asyncio.sleep(0.5)
        assert not phone.ws.closed
        assert await phone.ask(HELLO) == phone.welcome()


@run
async def test_ping_from_the_phone_is_answered_with_a_pong(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig), autoping=False)
        await phone.ws.ping(b"hi")
        msg = await phone.frame()
        assert (msg.type, msg.data) == (WSMsgType.PONG, b"hi")


# Source address

@pytest.mark.parametrize(
    "address, allowed",
    [
        ("10.0.0.0", True), ("10.255.255.255", True), ("9.255.255.255", False), ("11.0.0.0", False),
        ("172.16.0.0", True), ("172.31.255.255", True), ("172.15.255.255", False), ("172.32.0.0", False),
        ("192.168.0.0", True), ("192.168.255.255", True), ("192.167.255.255", False), ("192.169.0.0", False),
        ("169.254.0.0", True), ("169.254.255.255", True), ("169.253.255.255", False), ("169.255.0.0", False),
        ("127.0.0.1", True), ("127.255.255.255", True), ("126.255.255.255", False), ("128.0.0.0", False),
        ("8.8.8.8", False), ("100.64.0.1", False), ("0.0.0.0", False),
        ("::1", False), ("fe80::1", False), ("fe80::1%eth0", False), ("::ffff:192.168.1.5", False),
        ("", False), ("localhost", False), ("192.168.1", False), ("192.168.1.5.6", False), (None, False),
        (3232235777, False), (b"\xc0\xa8\x01\x01", False),
    ],
)
def test_source_address_allowlist(address, allowed):
    assert is_allowed_source(address) is allowed


@run
async def test_refused_peer_gets_no_http_response_at_all(tmp_path, monkeypatch):
    async with make_rig(tmp_path) as rig:
        monkeypatch.setattr(server_module, "_peer_address", lambda request: "8.8.8.8")
        reader, writer = await asyncio.open_connection("127.0.0.1", rig.server.port)
        writer.write(b"POST /v1/challenge HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        try:
            received = await reader.read()
        except ConnectionError:
            received = b""
        assert received == b""
        writer.close()
        with pytest.raises(aiohttp.ClientConnectionError):
            await rig.http.post(rig.url("/v1/challenge"))
        with pytest.raises(aiohttp.ClientError):
            await rig.http.ws_connect(rig.url("/v1/ws", "ws"))


def test_default_local_ip_uses_a_datagram_probe_and_only_returns_private_addresses(monkeypatch):
    class Probe:
        def __init__(self, result):
            self.result, self.connected = result, None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def connect(self, address):
            self.connected = address

        def getsockname(self):
            return (self.result, 5555)

    probes = []

    def fake(result):
        def factory(family, kind):
            assert (family, kind) == (socket.AF_INET, socket.SOCK_DGRAM)
            probes.append(Probe(result))
            return probes[-1]

        return factory

    for result, expected in (("192.168.4.7", "192.168.4.7"), ("8.8.4.4", None), ("127.0.0.1", None)):
        monkeypatch.setattr(socket, "socket", fake(result))
        assert default_local_ip() == expected
    assert probes[0].connected == ("10.255.255.255", 1)

    def unreachable(family, kind):
        raise OSError("network unreachable")

    monkeypatch.setattr(socket, "socket", unreachable)
    assert default_local_ip() is None


def test_throttle_blocks_after_the_failure_count_and_clears_after_the_window():
    throttle = AddressThrottle(3, 10_000)
    for t in (0, 100):
        throttle.record_failure("10.0.0.1", t)
        assert not throttle.blocked("10.0.0.1", t)
    throttle.record_failure("10.0.0.1", 200)
    assert throttle.blocked("10.0.0.1", 200) and throttle.blocked("10.0.0.1", 10_199)
    assert not throttle.blocked("10.0.0.1", 10_200) and not throttle.blocked("10.0.0.2", 200)


def test_throttle_forgets_failures_older_than_the_window_and_stays_bounded():
    throttle = AddressThrottle(3, 1000, table_max=4)
    throttle.record_failure("10.0.0.1", 0)
    throttle.record_failure("10.0.0.1", 500)
    throttle.record_failure("10.0.0.1", 1200)
    assert not throttle.blocked("10.0.0.1", 1200)
    for n in range(20):
        throttle.record_failure(f"10.0.1.{n}", 5000 + n)
    assert len(throttle._entries) <= 4


# Throttle through the server

async def _fail_http(rig, paired, times):
    phone = HttpPhone(rig, paired)
    wire = _tampered(paired)
    return [await phone.plain(wire) for _ in range(times)]


@run
async def test_repeated_authentication_failures_are_throttled_until_the_window_passes(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        results = await _fail_http(rig, paired, 20)
        assert results == [(401, {"error": "auth_failed"})] * 20
        phone = HttpPhone(rig, paired)
        # Throttled: even an authentic message is turned away without the receive procedure.
        assert await phone.plain(_sealed_by(paired)) == (429, {"error": "rate_limited"})
        assert await phone.get_challenge()
        stream = await StreamPhone.connect(rig, paired)
        assert await stream.plain(_sealed_by(paired)) == (None, {"type": "error", "error": "rate_limited"})
        rig.clock.advance(10_000)
        assert await phone.ask(HELLO) == phone.welcome()


@run
async def test_nineteen_failures_do_not_throttle(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        await _fail_http(rig, paired, 19)
        assert await HttpPhone(rig, paired).ask(HELLO) is not None


@run
async def test_stream_failures_count_towards_the_throttle(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        for _ in range(2):
            phone = await StreamPhone.connect(rig, paired)
            for _ in range(c.WS_PLAIN_ERROR_MAX):
                await phone.ws.send_bytes(_tampered(paired))
            await phone.closed()
        assert await HttpPhone(rig, paired).plain(_sealed_by(paired)) == (429, {"error": "rate_limited"})


@run
async def test_unknown_device_is_not_counted_as_an_authentication_failure(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        phone = HttpPhone(rig, paired)
        stranger = Sender(os.urandom(16), os.urandom(32)).seal(HELLO)
        for _ in range(25):
            assert await phone.plain(stranger) == (401, {"error": "unknown_device"})
        assert await HttpPhone(rig, paired).ask(HELLO) is not None


# Pairing over HTTP

async def _post(rig, path, body, **kwargs):
    async with rig.http.post(rig.url(path), data=body, **kwargs) as response:
        return response.status, response.content_type, await response.json()


def _pair_request(rig, name="Phone"):
    uri = rig.server.state()["pairing"]["uri"]
    return PhonePairing(uri, name, os.urandom(32), os.urandom(16))


@run
async def test_pairing_endpoints_reject_without_a_session(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = PhonePairing(
            rig.server.start_pairing()["pairing"]["uri"], "Phone", os.urandom(32), os.urandom(16)
        )
        rig.server.cancel_pairing()
        good = encode(phone.pair_request())
        assert await _post(rig, "/v1/pair", good) == (410, "application/json", {"error": "pair_expired"})
        assert await _post(rig, "/v1/pair", b"{}") == (400, "application/json", {"error": "bad_message"})
        confirm = encode({"deviceId": "00" * 16, "confirm": "00" * 32})
        assert await _post(rig, "/v1/pair/confirm", confirm) == (410, "application/json", {"error": "pair_expired"})
        assert await _post(rig, "/v1/pair/confirm", b"nope") == (400, "application/json", {"error": "bad_message"})


@run
async def test_pair_rejects_a_bad_body_a_wrong_token_and_a_reused_token(tmp_path):
    async with make_rig(tmp_path) as rig:
        rig.server.start_pairing()
        phone = _pair_request(rig)
        request = phone.pair_request()
        assert await _post(rig, "/v1/pair", b"not json") == (400, "application/json", {"error": "bad_message"})
        wrong = encode({**request, "token": "00" * 16})
        assert await _post(rig, "/v1/pair", wrong) == (401, "application/json", {"error": "token_invalid"})
        status, _, answer = await _post(rig, "/v1/pair", encode(request))
        assert status == 200 and set(answer) == {"pluginPublic", "pluginNonce", "deviceId"}
        assert await _post(rig, "/v1/pair", encode(request)) == (410, "application/json", {"error": "pair_expired"})


@run
async def test_confirm_with_the_wrong_proof_ends_the_session(tmp_path):
    async with make_rig(tmp_path) as rig:
        rig.server.start_pairing()
        phone = _pair_request(rig)
        _, _, answer = await _post(rig, "/v1/pair", encode(phone.pair_request()))
        confirm = phone.on_pair_response(answer)
        wrong = encode({**confirm, "confirm": "00" * 32})
        assert await _post(rig, "/v1/pair/confirm", wrong) == (401, "application/json", {"error": "confirm_failed"})
        assert rig.server.state()["pairing"] is None
        assert rig.server.state()["devices"] == []
        assert await _post(rig, "/v1/pair/confirm", encode(confirm)) == (410, "application/json", {"error": "pair_expired"})


@run
async def test_confirm_after_the_window_is_expired(tmp_path):
    async with make_rig(tmp_path) as rig:
        rig.server.start_pairing()
        phone = _pair_request(rig)
        _, _, answer = await _post(rig, "/v1/pair", encode(phone.pair_request()))
        confirm = phone.on_pair_response(answer)
        rig.clock.advance(c.PAIR_CONFIRM_TTL_S * 1000)
        assert await _post(rig, "/v1/pair/confirm", encode(confirm)) == (410, "application/json", {"error": "pair_expired"})
        assert rig.server.state()["pairing"] is None and rig.server.state()["devices"] == []


@run
async def test_five_failed_pair_requests_end_the_session(tmp_path):
    async with make_rig(tmp_path) as rig:
        rig.server.start_pairing()
        request = _pair_request(rig).pair_request()
        wrong = encode({**request, "token": "00" * 16})
        for _ in range(c.PAIR_MAX_FAILURES):
            assert await _post(rig, "/v1/pair", wrong) == (401, "application/json", {"error": "token_invalid"})
        assert rig.server.state()["pairing"] is None
        assert await _post(rig, "/v1/pair", encode(request)) == (410, "application/json", {"error": "pair_expired"})


# Paths, methods, sizes and versions

async def _call(rig, method, path, **kwargs):
    async with rig.http.request(method, rig.url(path), **kwargs) as response:
        return response.status, response.content_type, await response.json(), response.headers


@pytest.mark.parametrize(
    "method, path, status, allow",
    [
        ("GET", "/", 404, None),
        ("GET", "/nope", 404, None),
        ("POST", "/v1/nope", 404, None),
        ("POST", "/v1/cmd/", 404, None),
        ("POST", "/v1/pair/confirm/x", 404, None),
        ("POST", "/v0/cmd", 404, None),
        ("POST", "/v1x/cmd", 404, None),
        ("GET", "/v1/cmd", 405, "POST"),
        ("PUT", "/v1/challenge", 405, "POST"),
        ("DELETE", "/v1/pair", 405, "POST"),
        ("GET", "/v1/pair/confirm", 405, "POST"),
        ("POST", "/v1/ws", 405, "GET"),
    ],
)
@run
async def test_wrong_path_or_method(tmp_path, method, path, status, allow):
    async with make_rig(tmp_path) as rig:
        got, content_type, body, headers = await _call(rig, method, path)
        assert (got, content_type, body) == (status, "application/json", {"error": "bad_message"})
        assert headers.get("Allow") == allow


@pytest.mark.parametrize("path", ["/v2/cmd", "/v2/ws", "/v2/challenge", "/v9/anything/else", "/v" + "9" * 40 + "/cmd"])
@pytest.mark.parametrize("method", ["POST", "GET"])
@run
async def test_path_of_a_newer_version(tmp_path, method, path):
    async with make_rig(tmp_path) as rig:
        got, _, body, _ = await _call(rig, method, path)
        assert (got, body) == (426, {"error": "version_too_new", "maxVersion": 1})


@pytest.mark.parametrize(
    "path, cap", [("/v1/pair", c.PAIR_BODY_MAX), ("/v1/pair/confirm", c.PAIR_BODY_MAX), ("/v1/cmd", c.MAX_ENVELOPE_LEN)]
)
@run
async def test_oversize_body_is_refused_with_413(tmp_path, path, cap):
    async def chunked():
        for _ in range(3):
            yield bytes(cap)

    async with make_rig(tmp_path) as rig:
        rig.server.start_pairing()
        for kwargs in ({"data": bytes(cap + 1)}, {"data": chunked()}):
            got, content_type, body, _ = await _call(rig, "POST", path, **kwargs)
            assert (got, content_type, body) == (413, "application/json", {"error": "bad_message"})
        # Exactly at the cap the body is read and judged on its content instead.
        got, _, body, _ = await _call(rig, "POST", path, data=bytes(cap))
        assert (got, body) == (400, {"error": "bad_message"})


# Pairing session lifecycle

@run
async def test_pairing_session_lifecycle_and_notifications(tmp_path):
    async with make_rig(tmp_path) as rig:
        assert rig.server.state()["pairing"] is None
        before = rig.changes
        state = rig.server.start_pairing()
        assert rig.changes > before
        uri = parse_uri(state["pairing"]["uri"])
        assert (uri.host, uri.port, uri.name) == ("127.0.0.1", rig.server.port, HOSTNAME)
        assert uri.plugin_id == rig.store.plugin_id
        assert state["pairing"]["expiresInS"] == c.QR_TTL_S
        assert state["error"] is None

        rig.clock.advance(20_000)
        assert rig.server.state()["pairing"]["expiresInS"] == c.QR_TTL_S - 20

        before = rig.changes
        assert rig.server.cancel_pairing()["pairing"] is None
        assert rig.changes > before
        before = rig.changes
        rig.server.cancel_pairing()
        assert rig.changes == before


@run
async def test_second_pairing_session_invalidates_the_first_token(tmp_path):
    async with make_rig(tmp_path) as rig:
        first_uri = rig.server.start_pairing()["pairing"]["uri"]
        first = PhonePairing(first_uri, "Phone", os.urandom(32), os.urandom(16))
        second_uri = rig.server.start_pairing()["pairing"]["uri"]
        assert second_uri != first_uri
        status, _, body = await _post(rig, "/v1/pair", encode(first.pair_request()))
        assert (status, body) == (401, {"error": "token_invalid"})
        second = PhonePairing(second_uri, "Phone", os.urandom(32), os.urandom(16))
        assert (await _post(rig, "/v1/pair", encode(second.pair_request())))[0] == 200


@run
async def test_session_expiring_by_the_clock_is_gone_from_the_state(tmp_path):
    async with make_rig(tmp_path) as rig:
        rig.server.start_pairing()
        rig.clock.advance(c.QR_TTL_S * 1000)
        assert rig.server.state()["pairing"] is None


@run
async def test_session_expiring_on_its_own_notifies_the_panel(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "QR_TTL_S", 0.2)
    async with make_rig(tmp_path, clock_ms=lambda: int(asyncio.get_running_loop().time() * 1000)) as rig:
        rig.server.start_pairing()
        assert rig.server.state()["pairing"] is not None
        before = rig.changes
        await until(lambda: rig.changes > before)
        assert rig.server.state()["pairing"] is None
        assert any("pairing session expired" in r.getMessage() for r in rig.records)


@run
async def test_successful_pairing_and_connections_notify_the_panel(tmp_path):
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)
        assert any(s["pairing"] is None and len(s["devices"]) == 1 for s in rig.snapshots)
        assert rig.server.state()["devices"][0]["connected"] is False
        phone = await StreamPhone.connect(rig, paired)
        await phone.ask(HELLO)
        assert rig.server.state()["devices"][0]["connected"] is True
        assert rig.snapshots[-1]["devices"][0]["connected"] is True
        await phone.ws.close()
        await until(lambda: rig.snapshots[-1]["devices"][0]["connected"] is False)
        assert rig.server.state()["devices"][0]["connected"] is False


@run
async def test_pairing_without_an_address_or_without_listening_reports_an_error(tmp_path):
    async with make_rig(tmp_path, local_ip=lambda: None) as rig:
        state = rig.server.start_pairing()
        assert state["pairing"] is None and state["error"] == "No local network address"
    async with make_rig(tmp_path / "other", start=False) as idle:
        state = idle.server.start_pairing()
        assert state["listening"] is False and state["pairing"] is None and state["error"] == "Not listening"


@run
async def test_start_pairing_while_listening_clears_an_earlier_error(tmp_path):
    addresses = [None, "127.0.0.1"]
    async with make_rig(tmp_path, local_ip=lambda: addresses.pop(0)) as rig:
        assert rig.server.start_pairing()["error"] == "No local network address"
        state = rig.server.start_pairing()
        assert state["error"] is None and state["pairing"] is not None


# Port and lifecycle

@run
async def test_busy_stored_port_falls_back_and_the_bound_port_is_saved(tmp_path):
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    busy = blocker.getsockname()[1]
    try:
        async with make_rig(tmp_path, store_port=busy, port=None) as rig:
            assert rig.server.port not in (None, busy)
            assert rig.store.port == rig.server.port
            assert DeviceStore(rig.path).port == rig.server.port
            assert (await HttpPhone(rig, await pair(rig)).ask(HELLO))["type"] == "welcome"
    finally:
        blocker.close()


@run
async def test_free_stored_port_is_reused(tmp_path):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    free = probe.getsockname()[1]
    probe.close()
    async with make_rig(tmp_path, store_port=free, port=None) as rig:
        assert rig.server.port == free


@run
async def test_unusable_bind_address_leaves_the_server_not_listening(tmp_path):
    async with make_rig(tmp_path, bind_host="203.0.113.1", start=False) as rig:
        await rig.server.start()
        state = rig.server.state()
        assert (state["listening"], state["error"], rig.server.port) == (False, "Could not listen on the network", None)
        assert rig.server.start_pairing()["pairing"] is None


@run
async def test_stop_is_idempotent_and_closes_everything(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = await StreamPhone.connect(rig, await pair(rig))
        rig.server.start_pairing()
        await rig.server.stop()
        await rig.server.stop()
        assert (await phone.closed())[-1].type in CLOSED
        state = rig.server.state()
        assert (state["listening"], state["pairing"], rig.server.port) == (False, None, None)
        with pytest.raises(aiohttp.ClientError):
            await rig.http.post(f"http://127.0.0.1:{rig.store.port}/v1/challenge")


# Logging

@run
async def test_logs_never_carry_payloads_secrets_or_names(tmp_path):
    name, typed = "Alice's Phone", "hunter2pass"
    async with make_rig(tmp_path) as rig:
        uri = rig.server.start_pairing()["pairing"]["uri"]
        parsed = parse_uri(uri)
        phone = PhonePairing(uri, name, os.urandom(32), os.urandom(16))
        async with rig.http.post(rig.url("/v1/pair"), json=phone.pair_request()) as response:
            confirm = phone.on_pair_response(await response.json())
        async with rig.http.post(rig.url("/v1/pair/confirm"), json=confirm) as response:
            assert response.status == 200
        paired = Paired(phone.device_id, phone.device_key, name)

        challenges = []
        stream = await StreamPhone.connect(rig, paired)
        challenges.append(stream.challenge)
        assert await stream.ask(HELLO) == stream.welcome()
        rig.clock.advance(200)
        assert await stream.ask({"type": "press", "key": 4, "mods": 1}) == stream.ok()
        rig.clock.advance(200)
        assert await stream.ask({"type": "type", "text": typed}) == stream.ok()
        await stream.send({"type": "move", "dx": 7, "dy": 9})
        await stream.send({"type": "button", "button": "right", "state": "down"})
        assert await stream.ask({"type": "press", "key": 0x66, "mods": 0}) == stream.error("unsupported_key")
        assert await stream.ask({"type": "type", "text": "café"}) == stream.error("unsupported_char")
        await stream.ws.send_bytes(_tampered(paired))
        await stream.text()
        await stream.ws.send_str("text that must not be logged")
        await stream.text()
        http = HttpPhone(rig, paired)
        challenges.append(await http.get_challenge())
        await http.ask(HELLO, challenge=challenges[-1])
        await http.ask(HELLO, challenge=False)
        rig.kb.fail = True
        rig.clock.advance(200)
        assert await http.ask({"type": "press", "key": 4, "mods": 0}) == http.error("internal")
        await stream.ws.close()
        await until(lambda: any("stream closed" in r.getMessage() for r in rig.records))
        await rig.server.remove_device(paired.device_id.hex())

    secrets = [typed, paired.key.hex(), parsed.token.hex(), parsed.secret.hex(), name, uri, "text that must not be logged", *challenges]
    messages = [r.getMessage() for r in rig.records]
    for record in rig.records:
        assert record.exc_info is None and not record.args
        for secret in secrets:
            assert secret not in record.getMessage()
        assert "mods" not in record.getMessage() and "dx" not in record.getMessage()
    text = "\n".join(messages)
    for expected in (
        "listening on port",
        "pairing session started",
        "pairing session succeeded",
        f"device added {paired.device_id.hex()}",
        "stream opened from 127.0.0.1",
        "stream closed from 127.0.0.1",
        "stream message rejected: auth_failed",
        "stream message rejected: unsupported_key",
        "http message rejected: challenge_required",
        "press failed: InputError",
        f"device removed {paired.device_id.hex()}",
    ):
        assert expected in text, expected
