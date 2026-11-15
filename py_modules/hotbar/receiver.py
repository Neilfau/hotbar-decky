# Receive procedure for phone messages: replay window, challenges, rate limits and sealed answers.
import os
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from hotbar import constants as c
from hotbar import messages
from hotbar.crypto import AuthenticationError
from hotbar.envelope import Header, open_envelope, seal
from hotbar.messages import BodyError, Message

_MASK64 = 0xFFFFFFFFFFFFFFFF
# Pointer tokens are counted in thousandths so refill stays exact integer arithmetic.
_TOKEN = 1000
_BUCKET_FULL = c.POINTER_BURST * _TOKEN


@dataclass(frozen=True)
class PlainError:
    code: str

    def body(self) -> dict:
        body = {"error": self.code}
        if self.code == "version_too_new":
            body["maxVersion"] = c.MAX_VERSION
        return body

    @property
    def http_status(self) -> int:
        return messages.PLAIN_HTTP_STATUS[self.code]


@dataclass(frozen=True)
class SealedError:
    device_id: bytes
    sender_id: bytes
    counter: int
    code: str
    retry_after_ms: int | None
    silent_on_stream: bool

    def body(self) -> dict:
        return messages.error_body(self.sender_id, self.counter, self.code, self.retry_after_ms)


@dataclass(frozen=True)
class Accepted:
    device_id: bytes
    sender_id: bytes
    counter: int
    message: Message


Outcome = PlainError | SealedError | Accepted


@dataclass
class SenderState:
    highest: int
    bitmap: int


@dataclass
class Challenge:
    expires_at_ms: int
    address: str


@dataclass
class _Bucket:
    tokens: int  # thousandths of a token
    updated_ms: int


class Receiver:
    """State is held in plain attributes. `challenges` is in issue order (oldest first) and
    `senders` in least-recently-used order; `last_press_type_ms` and `buckets` are per device."""

    def __init__(
        self,
        device_key: Callable[[bytes], bytes | None],
        key_supported: Callable[[int], bool],
        char_supported: Callable[[str], bool],
        random: Callable[[int], bytes] = os.urandom,
        on_sender_evicted: Callable[[bytes, bytes], None] | None = None,
    ):
        self._device_key = device_key
        self._key_supported = key_supported
        self._char_supported = char_supported
        self._random = random
        self._on_sender_evicted = on_sender_evicted
        self.challenges: dict[bytes, Challenge] = {}
        self.senders: OrderedDict[tuple[bytes, bytes], SenderState] = OrderedDict()
        self.last_press_type_ms: dict[bytes, int] = {}
        self.buckets: dict[bytes, _Bucket] = {}

    def issue_challenge(self, address: str, now_ms: int) -> bytes:
        # ponytail: linear scans, bounded by the 256-challenge cap; index by address if that cap grows
        for expired in [k for k, v in self.challenges.items() if v.expires_at_ms <= now_ms]:
            del self.challenges[expired]
        from_address = [k for k, v in self.challenges.items() if v.address == address]
        for oldest in from_address[: max(0, len(from_address) - (c.CHALLENGE_MAX_PER_ADDRESS - 1))]:
            del self.challenges[oldest]
        while len(self.challenges) >= c.CHALLENGE_MAX_TOTAL:
            del self.challenges[next(iter(self.challenges))]
        challenge = self._random(c.CHALLENGE_LEN)
        self.challenges[challenge] = Challenge(now_ms + c.CHALLENGE_TTL_MS, address)
        return challenge

    def drop_sender(self, device_id: bytes, sender_id: bytes) -> None:
        self.senders.pop((device_id, sender_id), None)

    def drop_device(self, device_id: bytes) -> None:
        for key in [k for k in self.senders if k[0] == device_id]:
            del self.senders[key]
        self.last_press_type_ms.pop(device_id, None)
        self.buckets.pop(device_id, None)

    def receive(self, wire: bytes, now_ms: int) -> Outcome:
        # Everything up to the tag check is unauthenticated: it answers in plaintext and changes no state.
        if not c.MIN_ENVELOPE_LEN <= len(wire) <= c.MAX_ENVELOPE_LEN:
            return PlainError("bad_message")
        if wire[0] == 0:
            return PlainError("bad_message")
        if wire[0] > c.VERSION:
            return PlainError("version_too_new")
        if wire[1] != c.DIR_PHONE_TO_PLUGIN:
            return PlainError("bad_direction")
        device_key = self._device_key(Header.parse(wire).device_id)
        if device_key is None:
            return PlainError("unknown_device")
        try:
            header, body = open_envelope(device_key, wire)
        except AuthenticationError:
            return PlainError("auth_failed")

        def sealed(code: str, retry: int | None = None, silent: bool = False) -> SealedError:
            return SealedError(header.device_id, header.sender_id, header.counter, code, retry, silent)

        try:
            obj = messages.parse_json_object(body)
        except BodyError as exc:
            return sealed(exc.code)
        failure = self._check_sender(header, obj, now_ms)
        if failure:
            return sealed(failure)
        # The counter is spent from here on, even if the message is refused below.
        try:
            message = messages.validate(obj, self._key_supported, self._char_supported)
        except BodyError as exc:
            return sealed(exc.code)
        if isinstance(message, (messages.Press, messages.TypeText)):
            retry = self._gap_retry_ms(header.device_id, now_ms)
            if retry:
                return sealed("rate_limited", retry)
        elif isinstance(message, (messages.Move, messages.Scroll)):
            retry = self._bucket_retry_ms(header.device_id, now_ms)
            if retry:
                return sealed("rate_limited", retry, silent=True)
        return Accepted(header.device_id, header.sender_id, header.counter, message)

    def _check_sender(self, header: Header, obj: dict, now_ms: int) -> str | None:
        """Window check for a registered sender, challenge check for a new one."""
        key = (header.device_id, header.sender_id)
        state = self.senders.get(key)
        if state is None:
            return self._register(key, header.counter, obj, now_ms)
        failure = _window_check(state, header.counter)
        if failure is None:
            self.senders.move_to_end(key)
        return failure

    def _register(self, key: tuple[bytes, bytes], counter: int, obj: dict, now_ms: int) -> str | None:
        if "challenge" not in obj:
            return "challenge_required"
        challenge = messages.parse_hex(obj["challenge"], c.CHALLENGE_LEN)
        issued = None if challenge is None else self.challenges.get(challenge)
        if issued is None or now_ms >= issued.expires_at_ms:
            return "challenge_invalid"
        del self.challenges[challenge]
        if len(self.senders) >= c.SENDER_TABLE_MAX:
            evicted, _ = self.senders.popitem(last=False)
            if self._on_sender_evicted:
                self._on_sender_evicted(*evicted)
        self.senders[key] = SenderState(counter, _MASK64)
        return None

    def _gap_retry_ms(self, device_id: bytes, now_ms: int) -> int:
        """0 and the gap clock moves when the message may run, else the wait in ms."""
        last = self.last_press_type_ms.get(device_id)
        if last is not None and now_ms - last < c.GAP_PLUGIN_MS:
            return c.GAP_PLUGIN_MS - (now_ms - last)
        self.last_press_type_ms[device_id] = now_ms
        return 0

    def _bucket_retry_ms(self, device_id: bytes, now_ms: int) -> int:
        """0 and one token is drawn when the event may run, else the ms until a token is available."""
        bucket = self.buckets.setdefault(device_id, _Bucket(_BUCKET_FULL, now_ms))
        elapsed = max(0, now_ms - bucket.updated_ms)
        # POINTER_RATE_PER_S tokens a second is that many thousandths of a token per millisecond.
        bucket.tokens = min(_BUCKET_FULL, bucket.tokens + elapsed * c.POINTER_RATE_PER_S)
        bucket.updated_ms = now_ms
        if bucket.tokens >= _TOKEN:
            bucket.tokens -= _TOKEN
            return 0
        return max(1, -(-(_TOKEN - bucket.tokens) // c.POINTER_RATE_PER_S))


def _window_check(state: SenderState, n: int) -> str | None:
    if n > state.highest:
        d = n - state.highest
        state.bitmap = 1 if d >= c.WINDOW_SIZE else ((state.bitmap << d) & _MASK64) | 1
        state.highest = n
    elif n == state.highest:
        return "replayed"
    else:
        d = state.highest - n
        if d >= c.WINDOW_SIZE:
            return "counter_too_old"
        if state.bitmap >> d & 1:
            return "replayed"
        state.bitmap |= 1 << d
    return None


class ResponseSealer:
    """Seals the plugin's answers on one stream connection or one HTTP response."""

    def __init__(self, device_key: bytes, device_id: bytes, random: Callable[[int], bytes] = os.urandom):
        self._device_key = device_key
        self._device_id = device_id
        self._random = random
        self.sender_id = random(c.SENDER_ID_LEN)
        self._counter = 0

    def seal(self, body: dict) -> bytes:
        header = Header(
            c.VERSION,
            c.DIR_PLUGIN_TO_PHONE,
            self._device_id,
            self.sender_id,
            self._counter,
            self._random(c.SALT_LEN),
        )
        wire = seal(self._device_key, header, messages.encode_body(body))
        self._counter += 1
        return wire
