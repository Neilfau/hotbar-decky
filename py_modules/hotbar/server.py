# The plugin's network side: HTTP and WebSocket endpoints, pairing sessions, revocation and input execution.
import asyncio
import errno
import json
import logging
import math
import re
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field

from aiohttp import WSCloseCode, WSMsgType, web

from hotbar import constants as c
from hotbar import messages
from hotbar.input import keymap
from hotbar.input.injector import Injector
from hotbar.messages import BodyError, Button, Hello, Move, Press, Scroll, TypeText, Unpair
from hotbar.netutil import AddressThrottle, default_local_ip, is_allowed_source
from hotbar.pairing import PairingSession, reject_confirm_without_session, reject_without_session
from hotbar.receiver import Accepted, PlainError, Receiver, ResponseSealer, SealedError
from hotbar.store import Device, DeviceStore, StoreError

DEFAULT_PORT = 47126
QUEUE_MAX = 256  # accepted actions waiting for one stream connection's worker
THROTTLE_FAILURES = 20  # authentication failures from one address ...
THROTTLE_WINDOW_MS = 10_000  # ... within this long block it for this long
PING_MISSES_MAX = 2
CONNECTIONS_PER_ADDRESS = 8
CONNECTIONS_TOTAL = 64
KEEPALIVE_TIMEOUT_S = 15
BODY_TIMEOUT_S = 5.0
CHALLENGES_PER_SECOND = 16
REJECT_SUMMARY_MS = 60_000
WRITE_RETRY_S = 30
STORAGE_ERROR = "Key storage failed; a removed key may still be in the file"
CLOSE_TIMEOUT_S = 2.0
# Frames are checked against the protocol limits by hand, so the library cap only needs to sit a little above them.
WS_LIBRARY_LIMIT = c.MAX_ENVELOPE_LEN + 1024

_PATH_VERSION = re.compile(r"/v([0-9]+)/")
_CHALLENGE_REQUEST = {"type": "challenge"}


def _encode(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


def _json(status: int, obj: dict) -> web.Response:
    return web.Response(body=_encode(obj), status=status, content_type="application/json")


def _plain(code: str, status: int | None = None, headers: dict | None = None) -> web.Response:
    error = PlainError(code)
    return web.Response(
        body=_encode(error.body()),
        status=error.http_status if status is None else status,
        content_type="application/json",
        headers=headers,
    )


def _peer_address(request: web.BaseRequest) -> str | None:
    peername = request.transport.get_extra_info("peername") if request.transport else None
    return peername[0] if peername else None


class _BodyTimeout(Exception):
    """The request body did not arrive within BODY_TIMEOUT_S."""


async def _read_body(request: web.BaseRequest, cap: int) -> bytes | None:
    """The request body, or None when it is longer than `cap`. Raises _BodyTimeout when it arrives too slowly."""
    if request.content_length is not None and request.content_length > cap:
        return None
    body = bytearray()
    try:
        async with asyncio.timeout(BODY_TIMEOUT_S):
            async for chunk in request.content.iter_chunked(4096):
                body += chunk
                if len(body) > cap:
                    return None
    except TimeoutError:
        raise _BodyTimeout from None
    return bytes(body)


class _ConnectionCaps:
    """Decides at connection time whether a new connection is kept: only allowed source addresses, at most
    `per_address` open from one address and `total` overall. Refused ones are aborted before any byte is read."""

    def __init__(self, per_address: int, total: int):
        self._per_address = per_address
        self._total = total
        self._open: dict[object, str] = {}
        self._counts: dict[str, int] = {}

    def admit(self, handler: object, address: str | None) -> bool:
        if not is_allowed_source(address):
            return False
        if len(self._open) >= self._total or self._counts.get(address, 0) >= self._per_address:
            return False
        self._open[handler] = address
        self._counts[address] = self._counts.get(address, 0) + 1
        return True

    def release(self, handler: object) -> None:
        address = self._open.pop(handler, None)
        if address is None:
            return
        if self._counts[address] <= 1:
            del self._counts[address]
        else:
            self._counts[address] -= 1


def _limit_connections(server: web.Server, caps: _ConnectionCaps) -> None:
    """Puts `caps` in front of the server's per-connection callbacks."""
    made, lost = server.connection_made, server.connection_lost

    def connection_made(handler, transport) -> None:
        made(handler, transport)
        peername = transport.get_extra_info("peername")
        if not caps.admit(handler, peername[0] if peername else None):
            transport.abort()

    def connection_lost(handler, exc=None) -> None:
        caps.release(handler)
        lost(handler, exc)

    server.connection_made, server.connection_lost = connection_made, connection_lost


def _quiet_logger(parent: logging.Logger) -> logging.Logger:
    """A logger for the HTTP library that writes nothing, so malformed requests leave no log lines."""
    quiet = logging.getLogger(f"{parent.name}.http")
    quiet.setLevel(logging.CRITICAL + 1)
    quiet.propagate = False
    return quiet


@dataclass(eq=False)
class _Conn:
    """One stream connection. `devices` are those that sent an authentic message, `senders` those
    whose messages were accepted; both are released when it closes."""

    ws: web.WebSocketResponse
    peer: str
    transport: asyncio.Transport | None
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(QUEUE_MAX))
    authentic: bool = False
    plain_errors: int = 0
    pongs: int = 0
    devices: set[bytes] = field(default_factory=set)
    senders: set[tuple[bytes, bytes]] = field(default_factory=set)
    sealers: dict[bytes, ResponseSealer] = field(default_factory=dict)
    worker: asyncio.Task | None = None
    watchers: list[asyncio.Task] = field(default_factory=list)


class HotBarServer:
    def __init__(
        self,
        *,
        store: DeviceStore,
        injector: Injector,
        logger: logging.Logger,
        hostname: str,
        local_ip: Callable[[], str | None] = default_local_ip,
        on_change: Callable[[], None] | None = None,
        port: int | None = None,
        bind_host: str = "0.0.0.0",
        clock_ms: Callable[[], int] | None = None,
        auth_timeout_s: float = c.WS_AUTH_TIMEOUT_S,
        ping_interval_s: float = c.WS_PING_INTERVAL_S,
        plain_error_max: int = c.WS_PLAIN_ERROR_MAX,
        throttle_failures: int = THROTTLE_FAILURES,
        throttle_window_ms: int = THROTTLE_WINDOW_MS,
        challenges_per_second: int = CHALLENGES_PER_SECOND,
    ):
        self._store = store
        self._injector = injector
        self._logger = logger
        self._hostname = hostname
        self._local_ip = local_ip
        self._on_change = on_change
        self._port = port
        self._bind_host = bind_host
        self._clock_ms = clock_ms or (lambda: int(time.monotonic() * 1000))
        self._auth_timeout_s = auth_timeout_s
        self._ping_interval_s = ping_interval_s
        self._plain_error_max = plain_error_max
        self._throttle = AddressThrottle(throttle_failures, throttle_window_ms)
        self._challenge_rate = AddressThrottle(challenges_per_second, 1000)
        self._reject_counts: dict[str, int] = {}
        self._reject_since_ms: int | None = None
        self._write_timer: asyncio.TimerHandle | None = None
        self._receiver = Receiver(
            self._device_key,
            keymap.key_supported,
            keymap.char_supported,
            on_sender_evicted=self._on_sender_evicted,
        )
        self.port: int | None = None
        self._runner: web.AppRunner | None = None
        self._error: str | None = None
        self._conns: set[_Conn] = set()
        self._http_tasks: dict[bytes, set[asyncio.Task]] = {}
        self._tasks: set[asyncio.Task] = set()
        self._pairing: PairingSession | None = None
        self._pairing_timer: asyncio.TimerHandle | None = None

    # Lifecycle

    async def start(self) -> None:
        if self._runner is not None:
            return
        app = web.Application(middlewares=[self._guard])
        app.router.add_route("*", "/{tail:.*}", self._route)
        app.on_response_prepare.append(self._drop_server_header)
        runner = web.AppRunner(
            app,
            access_log=None,
            logger=_quiet_logger(self._logger),
            shutdown_timeout=1.0,
            keepalive_timeout=KEEPALIVE_TIMEOUT_S,
        )
        await runner.setup()
        _limit_connections(runner.server, _ConnectionCaps(CONNECTIONS_PER_ADDRESS, CONNECTIONS_TOTAL))
        try:
            port = await self._listen(runner)
        except OSError as exc:
            await runner.cleanup()
            self._logger.warning(f"could not listen: {type(exc).__name__}")
            self._error = "Could not listen on the network"
            return
        self._runner = runner
        self.port = port
        self._error = None
        if port != self._store.port:
            try:
                self._store.set_port(port)
            except StoreError:
                self._logger.warning("could not save the listening port")
        self._logger.info(f"listening on port {port}")

    async def stop(self) -> None:
        runner, self._runner = self._runner, None
        if runner is None:
            return
        self.port = None
        for tasks in self._http_tasks.values():
            for task in tasks:
                task.cancel()
        conns = list(self._conns)
        for conn in conns:
            conn.worker.cancel()
        await asyncio.gather(*(self._close_ws(conn, WSCloseCode.GOING_AWAY) for conn in conns))
        self._end_pairing("stopped")
        if self._write_timer is not None:
            self._write_timer.cancel()
            self._write_timer = None
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._release_all()
        await runner.cleanup()
        self._logger.info("stopped")
        self._changed()

    async def _listen(self, runner: web.AppRunner) -> int:
        wanted = self._port if self._port is not None else (self._store.port or DEFAULT_PORT)
        for port in (wanted, 0):
            site = web.TCPSite(runner, self._bind_host, port)
            try:
                await site.start()
            except OSError as exc:
                if exc.errno != errno.EADDRINUSE or port == 0:
                    raise
                continue
            return runner.addresses[0][1]
        raise AssertionError("unreachable")

    # Panel interface

    @property
    def _listening(self) -> bool:
        return self._runner is not None

    def state(self) -> dict:
        now_s = self._now_s()
        pairing = None
        session = self._pairing
        if session is not None and session.is_active(now_s):
            pairing = {"uri": session.uri, "expiresInS": math.ceil(session.expires_in_s(now_s))}
        connected = set().union(*(conn.devices for conn in self._conns))
        return {
            "listening": self._listening,
            "error": self._error,
            "devices": [
                {
                    "deviceId": d.device_id.hex(),
                    "name": d.name,
                    "createdAt": d.created_at,
                    "connected": d.device_id in connected,
                }
                for d in self._store.devices()
            ],
            "pairing": pairing,
        }

    def start_pairing(self) -> dict:
        self._end_pairing("replaced")
        address = self._local_ip() if self._listening else None
        if not self._listening:
            self._error = self._error or "Not listening"
        elif address is None:
            self._error = self._storage_error() or "No local network address"
        else:
            try:
                self._pairing = PairingSession(
                    plugin_id=self._store.plugin_id,
                    host=address,
                    port=self.port,
                    hostname=self._hostname,
                    now_s=self._now_s(),
                )
            except ValueError:
                self._error = self._storage_error() or "Could not create the pairing code"
            else:
                self._error = self._storage_error()
                self._logger.info("pairing session started")
                self._arm_pairing_timer()
        self._changed()
        return self.state()

    def cancel_pairing(self) -> dict:
        self._end_pairing("cancelled")
        return self.state()

    async def remove_device(self, device_id_hex: str) -> dict:
        device_id = messages.parse_hex(device_id_hex, c.DEVICE_ID_LEN)
        if device_id is not None:
            await self._remove_one(device_id)
        return self.state()

    async def remove_all_devices(self) -> dict:
        ids = [d.device_id for d in self._store.devices()]
        await self._revoke(ids, self._store.remove_all)
        return self.state()

    # Pairing session

    def _now_s(self) -> float:
        return self._clock_ms() / 1000

    def _end_pairing(self, reason: str) -> None:
        session, self._pairing = self._pairing, None
        if self._pairing_timer is not None:
            self._pairing_timer.cancel()
            self._pairing_timer = None
        if session is not None:
            session.end()
            self._logger.info(f"pairing session {reason}")
            self._changed()

    def _arm_pairing_timer(self) -> None:
        if self._pairing_timer is not None:
            self._pairing_timer.cancel()
        delay = self._pairing.expires_in_s(self._now_s()) + 0.05
        self._pairing_timer = asyncio.get_running_loop().call_later(delay, self._pairing_tick)

    def _pairing_tick(self) -> None:
        self._pairing_timer = None
        if self._pairing is None:
            return
        if self._pairing.is_active(self._now_s()):
            self._arm_pairing_timer()
        else:
            self._end_pairing("expired")

    def _after_pairing_request(self) -> None:
        session = self._pairing
        if session is None:
            return
        if session.succeeded:
            self._end_pairing("succeeded")
        elif not session.is_active(self._now_s()):
            self._end_pairing("ended")
        else:
            self._arm_pairing_timer()

    def _commit(self, device: Device) -> None:
        self._store.add(device)
        self._logger.info(f"device added {device.device_id.hex()}")

    # HTTP

    async def _drop_server_header(self, request: web.Request, response: web.StreamResponse) -> None:
        response.headers.pop("Server", None)

    @web.middleware
    async def _guard(self, request: web.Request, handler):
        if self._runner is None or not is_allowed_source(_peer_address(request)):
            # No status line at all: the connection just ends. The response below is never written.
            return self._hang_up(request)
        try:
            return await handler(request)
        except web.HTTPException:
            raise
        except _BodyTimeout:
            return self._hang_up(request)
        except Exception as exc:
            self._logger.warning(f"request failed: {type(exc).__name__}")
            return _plain("internal")

    @staticmethod
    def _hang_up(request: web.Request) -> web.Response:
        if request.transport is not None:
            request.transport.close()
        return web.Response()

    async def _route(self, request: web.Request) -> web.StreamResponse:
        match = _PATH_VERSION.match(request.path)
        if match and (len(match[1]) > 9 or int(match[1]) > c.VERSION):
            return _plain("version_too_new")
        routes = {
            "/v1/pair": ("POST", self._pair),
            "/v1/pair/confirm": ("POST", self._pair_confirm),
            "/v1/challenge": ("POST", self._challenge),
            "/v1/cmd": ("POST", self._cmd),
            "/v1/ws": ("GET", self._stream),
        }
        route = routes.get(request.path)
        if route is None:
            return _plain("bad_message", 404)
        method, handler = route
        if request.method != method:
            return _plain("bad_message", 405, {"Allow": method})
        return await handler(request)

    async def _pair(self, request: web.Request) -> web.Response:
        body = await _read_body(request, c.PAIR_BODY_MAX)
        if body is None:
            return _plain("bad_message", 413)
        if self._pairing is None:
            status, answer = reject_without_session(body)
        else:
            taken = {d.device_id for d in self._store.devices()}
            status, answer = self._pairing.pair(body, self._now_s(), taken)
        self._after_pairing_request()
        return _json(status, answer)

    async def _pair_confirm(self, request: web.Request) -> web.Response:
        body = await _read_body(request, c.PAIR_BODY_MAX)
        if body is None:
            return _plain("bad_message", 413)
        if self._pairing is None:
            status, answer = reject_confirm_without_session(body)
        else:
            status, answer = self._pairing.confirm(body, self._now_s(), self._commit)
        self._after_pairing_request()
        return _json(status, answer)

    def _issue_challenge(self, peer: str) -> bytes | None:
        """A new challenge, or None when `peer` has asked for too many a second."""
        now = self._clock_ms()
        if self._challenge_rate.blocked(peer, now):
            return None
        self._challenge_rate.record_failure(peer, now)
        return self._receiver.issue_challenge(peer, now)

    async def _challenge(self, request: web.Request) -> web.Response:
        if request.content_length or "Transfer-Encoding" in request.headers:
            return _plain("bad_message", 413)
        challenge = self._issue_challenge(_peer_address(request) or "")
        if challenge is None:
            return _plain("rate_limited")
        return _json(200, {"challenge": challenge.hex(), "ttlMs": c.CHALLENGE_TTL_MS})

    async def _cmd(self, request: web.Request) -> web.Response:
        wire = await _read_body(request, c.MAX_ENVELOPE_LEN)
        if wire is None:
            return _plain("bad_message", 413)
        peer = _peer_address(request) or ""
        now = self._clock_ms()
        if self._throttle.blocked(peer, now):
            return _plain("rate_limited")
        outcome = self._receiver.receive(wire, now)
        if isinstance(outcome, PlainError):
            self._rejected("http", outcome.code)
            self._throttle.record_failure(peer, now)
            return _plain(outcome.code)
        if isinstance(outcome, SealedError):
            self._rejected("http", outcome.code)
            return self._sealed_response(outcome.device_id, outcome.body())
        answer = await self._execute_tracked(outcome)
        response = self._sealed_response(outcome.device_id, answer)
        if isinstance(outcome.message, Unpair) and self._store.get(outcome.device_id) is not None:
            # Sealed above, which needs the key. The device is gone before the phone can see the ok, so
            # nothing it sent behind the unpair can still run.
            revocation = self._revoke_now([outcome.device_id], lambda: self._store.remove(outcome.device_id))
            try:
                await response.prepare(request)
                await response.write_eof()
            finally:
                self._spawn(self._revoke_finish(*revocation))
        return response

    def _sealed_response(self, device_id: bytes, body: dict) -> web.Response:
        device = self._store.get(device_id)
        if device is None:
            return _plain("unknown_device")
        wire = ResponseSealer(device.key, device_id).seal(body)
        return web.Response(body=wire, content_type="application/octet-stream")

    async def _execute_tracked(self, accepted: Accepted) -> dict:
        """Runs an HTTP command so that revoking its device can cancel it."""
        task = asyncio.current_task()
        tasks = self._http_tasks.setdefault(accepted.device_id, set())
        tasks.add(task)
        try:
            return await self._execute(accepted)
        finally:
            tasks.discard(task)
            if not tasks:
                self._http_tasks.pop(accepted.device_id, None)

    # Stream

    async def _stream(self, request: web.Request) -> web.StreamResponse:
        ws = web.WebSocketResponse(
            autoping=False,
            compress=False,
            max_msg_size=WS_LIBRARY_LIMIT,
            timeout=CLOSE_TIMEOUT_S,
        )
        if not ws.can_prepare(request).ok:
            return _plain("bad_message")
        await ws.prepare(request)
        conn = _Conn(ws, _peer_address(request) or "", request.transport)
        self._conns.add(conn)
        self._logger.info(f"stream opened ({len(self._conns)} open)")
        conn.worker = asyncio.create_task(self._worker(conn))
        conn.watchers = [asyncio.create_task(self._watch_auth(conn)), asyncio.create_task(self._watch_pings(conn))]
        try:
            await self._send_challenge(conn)
            await self._read(conn)
        except ConnectionError:
            pass
        except Exception as exc:
            self._logger.warning(f"stream failed: {type(exc).__name__}")
        finally:
            await self._cleanup(conn)
        return ws

    async def _read(self, conn: _Conn) -> None:
        while True:
            msg = await conn.ws.receive()
            if msg.type is WSMsgType.BINARY:
                keep_open = await self._on_binary(conn, msg.data)
            elif msg.type is WSMsgType.TEXT:
                keep_open = await self._on_text(conn, msg.data)
            elif msg.type is WSMsgType.PING:
                await conn.ws.pong(msg.data)
                keep_open = True
            elif msg.type is WSMsgType.PONG:
                conn.pongs += 1
                keep_open = True
            else:
                keep_open = False
            if not keep_open:
                return

    async def _on_text(self, conn: _Conn, text: str) -> bool:
        data = text.encode()
        if len(data) <= c.TEXT_FRAME_MAX:
            try:
                if messages.parse_object(data) == _CHALLENGE_REQUEST:
                    return await self._send_challenge(conn)
            except BodyError:
                pass
        return await self._send_plain(conn, PlainError("bad_message"), self._clock_ms())

    async def _on_binary(self, conn: _Conn, wire: bytes) -> bool:
        if len(wire) > c.MAX_ENVELOPE_LEN:
            self._rejected("stream", "frame_too_large")
            await self._close_ws(conn, WSCloseCode.MESSAGE_TOO_BIG)
            return False
        now = self._clock_ms()
        if self._throttle.blocked(conn.peer, now):
            return await self._send_plain(conn, PlainError("rate_limited"))
        outcome = self._receiver.receive(wire, now)
        if isinstance(outcome, PlainError):
            self._rejected("stream", outcome.code)
            return await self._send_plain(conn, outcome, now)
        conn.authentic = True
        conn.senders.add((outcome.device_id, outcome.sender_id))
        if outcome.device_id not in conn.devices:
            conn.devices.add(outcome.device_id)
            self._changed()
        if isinstance(outcome, SealedError):
            self._rejected("stream", outcome.code, silent=outcome.silent_on_stream)
            if not outcome.silent_on_stream:
                await self._send_sealed(conn, outcome.device_id, outcome.body())
            return True
        try:
            conn.queue.put_nowait(outcome)
        except asyncio.QueueFull:
            self._rejected("stream", "queue_full")
            await self._close_ws(conn, WSCloseCode.POLICY_VIOLATION)
            return False
        return True

    async def _send_challenge(self, conn: _Conn) -> bool:
        """Sends a challenge, or the rate_limited error when the address asks for too many; False once the socket is closed."""
        challenge = self._issue_challenge(conn.peer)
        if challenge is None:
            return await self._send_plain(conn, PlainError("rate_limited"))
        await conn.ws.send_str(
            json.dumps({"type": "challenge", "challenge": challenge.hex(), "ttlMs": c.CHALLENGE_TTL_MS}, separators=(",", ":"))
        )
        return True

    async def _send_plain(self, conn: _Conn, error: PlainError, counted_at_ms: int | None = None) -> bool:
        """Sends a plaintext error frame; False once the socket has had its fill of them and is closed.
        Given a time, the error also counts against the source address."""
        if counted_at_ms is not None:
            self._throttle.record_failure(conn.peer, counted_at_ms)
        conn.plain_errors += 1
        await conn.ws.send_str(json.dumps({"type": "error", **error.body()}, separators=(",", ":")))
        if conn.plain_errors < self._plain_error_max:
            return True
        await self._close_ws(conn, WSCloseCode.POLICY_VIOLATION)
        return False

    def _seal(self, conn: _Conn, device_id: bytes, body: dict) -> bytes | None:
        sealer = conn.sealers.get(device_id)
        if sealer is None:
            device = self._store.get(device_id)
            if device is None:
                return None  # revoked a moment ago; the socket is being closed
            sealer = conn.sealers[device_id] = ResponseSealer(device.key, device_id)
        return sealer.seal(body)

    async def _send_sealed(self, conn: _Conn, device_id: bytes, body: dict) -> None:
        wire = self._seal(conn, device_id, body)
        if wire is not None:
            await conn.ws.send_bytes(wire)

    async def _worker(self, conn: _Conn) -> None:
        """Runs the connection's accepted actions one at a time, in the order they arrived."""
        try:
            while True:
                accepted = await conn.queue.get()
                if self._store.get(accepted.device_id) is None:
                    continue  # its device was revoked after the frame was accepted
                answer = await self._execute(accepted)
                if isinstance(accepted.message, Unpair):
                    await self._acknowledge_unpair(conn, accepted.device_id, answer)
                    continue
                silent = answer["type"] == "ok" and isinstance(accepted.message, (Move, Button, Scroll))
                if not silent:
                    await self._send_sealed(conn, accepted.device_id, answer)
        except ConnectionError:
            pass
        except Exception as exc:
            self._logger.warning(f"stream worker failed: {type(exc).__name__}")
            await self._close_ws(conn, WSCloseCode.INTERNAL_ERROR)

    async def _acknowledge_unpair(self, conn: _Conn, device_id: bytes, answer: dict) -> None:
        # Sealed first, which needs the key. The device is gone before the phone can see the ok, so nothing
        # queued behind the unpair can run. This task is the connection's worker: it must not cancel itself
        # before the ok is out, so the rest of the revocation waits for a task of its own.
        wire = self._seal(conn, device_id, answer)
        revocation = self._revoke_now(
            [device_id], lambda: self._store.remove(device_id), keep=asyncio.current_task()
        )
        try:
            if wire is not None:
                await conn.ws.send_bytes(wire)
        finally:
            self._spawn(self._revoke_finish(*revocation))

    async def _watch_auth(self, conn: _Conn) -> None:
        await asyncio.sleep(self._auth_timeout_s)
        if not conn.authentic:
            self._rejected("stream", "auth_timeout")
            await self._close_ws(conn, WSCloseCode.POLICY_VIOLATION)

    async def _watch_pings(self, conn: _Conn) -> None:
        missed = 0
        waiting_for = None  # the pong count when the last ping went out
        try:
            while True:
                await asyncio.sleep(self._ping_interval_s)
                missed = missed + 1 if waiting_for == conn.pongs else 0
                if missed >= PING_MISSES_MAX:
                    self._rejected("stream", "ping_timeout")
                    await self._close_ws(conn, WSCloseCode.POLICY_VIOLATION)
                    return
                waiting_for = conn.pongs
                await conn.ws.ping()
        except ConnectionError:
            pass

    async def _close_ws(self, conn: _Conn, code: WSCloseCode) -> None:
        # Its own task, so that cancelling the caller (cleanup does that to the watchers) cannot cut
        # the closing handshake short.
        task = asyncio.get_running_loop().create_task(self._close_handshake(conn, code))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        await asyncio.shield(task)

    async def _close_handshake(self, conn: _Conn, code: WSCloseCode) -> None:
        try:
            await asyncio.wait_for(conn.ws.close(code=code), CLOSE_TIMEOUT_S)
        except (TimeoutError, ConnectionError):
            # The peer will not finish the closing handshake, so the connection is cut.
            if conn.transport is not None:
                conn.transport.abort()

    async def _cleanup(self, conn: _Conn) -> None:
        """Runs when a stream connection ends for any reason."""
        self._conns.discard(conn)
        tasks = [conn.worker, *conn.watchers]
        for task in tasks:
            task.cancel()
        # The cancelled worker lets go of any key it was holding before the owners are released.
        await asyncio.gather(*tasks, return_exceptions=True)
        for device_id, sender_id in conn.senders:
            self._receiver.drop_sender(device_id, sender_id)
        self._logger.info(f"stream closed ({len(self._conns)} open)")
        if conn.devices:
            self._changed()
        for owner in conn.senders:
            await self._release(owner)

    # Actions and revocation

    async def _execute(self, accepted: Accepted) -> dict:
        """Runs one accepted message and returns the answer to seal."""
        message = accepted.message
        owner = (accepted.device_id, accepted.sender_id)
        try:
            if isinstance(message, Hello):
                return messages.welcome_body(
                    accepted.sender_id, accepted.counter, self._store.plugin_id, self._hostname
                )
            if isinstance(message, Press):
                await self._injector.press(message.key, message.mods)
            elif isinstance(message, TypeText):
                await self._injector.type_text(message.text, message.open, message.submit)
            elif isinstance(message, Move):
                await self._injector.move(message.dx, message.dy)
            elif isinstance(message, Scroll):
                await self._injector.scroll(message.dx, message.dy)
            elif isinstance(message, Button):
                await self._injector.button(owner, message.button, message.down)
        except Exception as exc:
            self._logger.warning(f"{message.type_name} failed: {type(exc).__name__}")
            return messages.error_body(accepted.sender_id, accepted.counter, "internal")
        return messages.ok_body(accepted.sender_id, accepted.counter)

    def _device_key(self, device_id: bytes) -> bytes | None:
        device = self._store.get(device_id)
        return None if device is None else device.key

    async def _remove_one(self, device_id: bytes) -> None:
        if self._store.get(device_id) is not None:
            await self._revoke([device_id], lambda: self._store.remove(device_id))

    async def _revoke(self, device_ids: list[bytes], remove: Callable[[], object]) -> None:
        await self._revoke_finish(*self._revoke_now(device_ids, remove))

    def _revoke_now(
        self, device_ids: list[bytes], remove: Callable[[], object], keep: asyncio.Task | None = None
    ) -> tuple[list[tuple[bytes, bytes]], list[_Conn]]:
        """Takes the devices out of the store and the receiver and stops their work, without yielding, so
        that from here on nothing from them is accepted. `_revoke_finish` closes and frees what is left.
        Returns what it needs. The `keep` task is not cancelled here."""
        try:
            remove()
            self._error = self._storage_error()
        except StoreError:
            # The store has already dropped the keys from memory, so the devices are revoked either way.
            self._logger.warning("could not save the device list after a removal")
            self._error = STORAGE_ERROR
        if self._error == STORAGE_ERROR:
            self._arm_write_retry()
        owners = []
        for device_id in device_ids:
            owners += [key for key in self._receiver.senders if key[0] == device_id]
            self._receiver.drop_device(device_id)
            for task in self._http_tasks.pop(device_id, ()):
                task.cancel()
            self._logger.info(f"device removed {device_id.hex()}")
        self._changed()
        doomed = [conn for conn in self._conns if conn.devices.intersection(device_ids)]
        for conn in doomed:
            if conn.worker is not keep:
                conn.worker.cancel()
        return owners, doomed

    async def _revoke_finish(self, owners: list[tuple[bytes, bytes]], doomed: list[_Conn]) -> None:
        for conn in doomed:
            conn.worker.cancel()
        await asyncio.gather(*(self._close_ws(conn, WSCloseCode.GOING_AWAY) for conn in doomed))
        for owner in owners:
            await self._release(owner)

    def _on_sender_evicted(self, device_id: bytes, sender_id: bytes) -> None:
        self._spawn(self._release((device_id, sender_id)))

    async def _release(self, owner: tuple[bytes, bytes]) -> None:
        try:
            await self._injector.release_owner(owner)
        except Exception as exc:
            self._logger.warning(f"could not release a button: {type(exc).__name__}")

    async def _release_all(self) -> None:
        try:
            await self._injector.release_all()
        except Exception as exc:
            self._logger.warning(f"could not release held input: {type(exc).__name__}")

    # Helpers

    def _spawn(self, work: Coroutine) -> None:
        task = asyncio.get_running_loop().create_task(self._logged(work))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _logged(self, work: Coroutine) -> None:
        try:
            await work
        except Exception as exc:
            self._logger.warning(f"background task failed: {type(exc).__name__}")

    def _storage_error(self) -> str | None:
        return STORAGE_ERROR if self._store.write_pending else None

    def _arm_write_retry(self) -> None:
        if self._write_timer is None and self._runner is not None:
            self._write_timer = asyncio.get_running_loop().call_later(WRITE_RETRY_S, self._retry_write)

    def _retry_write(self) -> None:
        self._write_timer = None
        if self._store.retry_write():
            if self._error == STORAGE_ERROR:
                self._error = None
                self._changed()
        else:
            self._arm_write_retry()

    def _rejected(self, channel: str, code: str, silent: bool = False) -> None:
        """Logs a refused message at debug, plus a count per code in one info line a minute at most."""
        self._logger.debug(f"{channel} message rejected: {code}")
        if silent:
            return
        now = self._clock_ms()
        if self._reject_since_ms is None:
            self._reject_since_ms = now
        self._reject_counts[code] = self._reject_counts.get(code, 0) + 1
        if now - self._reject_since_ms >= REJECT_SUMMARY_MS:
            counts = ", ".join(f"{code}={n}" for code, n in sorted(self._reject_counts.items()))
            self._logger.info(f"messages rejected since the last summary: {counts}")
            self._reject_counts.clear()
            self._reject_since_ms = None

    def _changed(self) -> None:
        if self._on_change is None:
            return
        try:
            self._on_change()
        except Exception as exc:
            self._logger.warning(f"change callback failed: {type(exc).__name__}")
