# Network-surface limits of the server: connection caps, source refusal, error counting, log volume,
# challenge rate, sender cleanup and the pending key-file write.
import asyncio
import logging

import aiohttp
import pytest

from hotbar import constants as c
from hotbar import server as server_module
from hotbar.store import DeviceStore, StoreError
from test_server import (
    HELLO,
    HttpPhone,
    StreamPhone,
    _sealed_by,
    make_rig,
    open_phone,
    pair,
    run,
    until,
)

CHALLENGE_REQUEST = b"POST /v1/challenge HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
CHALLENGE_THEN_CLOSE = b"POST /v1/challenge HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


async def exchange(rig, data, wait=1.0):
    """Sends `data` on a new raw connection and returns every byte the server sent before it ended."""
    reader, writer = await asyncio.open_connection("127.0.0.1", rig.server.port)
    try:
        writer.write(data)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), wait)
    except ConnectionError:
        return b""
    finally:
        writer.close()


async def open_raw(rig, count):
    return [await asyncio.open_connection("127.0.0.1", rig.server.port) for _ in range(count)]


async def aborted(reader, wait=1.0):
    """True when the server cut the connection without sending a byte."""
    try:
        return await asyncio.wait_for(reader.read(), wait) == b""
    except ConnectionError:
        return True


# Connection caps

@run
async def test_ninth_connection_from_one_address_is_aborted_without_a_byte(tmp_path):
    async with make_rig(tmp_path) as rig:
        held = await open_raw(rig, 8)
        reader, writer = await asyncio.open_connection("127.0.0.1", rig.server.port)
        writer.write(CHALLENGE_REQUEST)
        assert await aborted(reader)
        # The first eight are still served, and a closed one frees its place.
        held[0][1].write(CHALLENGE_REQUEST)
        assert (await asyncio.wait_for(held[0][0].readuntil(b"\r\n"), 1)).startswith(b"HTTP/1.1 200")
        held[1][1].close()
        await asyncio.sleep(0.05)
        assert (await exchange(rig, CHALLENGE_THEN_CLOSE)).startswith(b"HTTP/1.1 200")
        for _, w in held:
            w.close()


@run
async def test_connection_beyond_the_total_cap_is_aborted_without_a_byte(tmp_path, monkeypatch):
    monkeypatch.setattr(server_module, "CONNECTIONS_TOTAL", 3)
    async with make_rig(tmp_path) as rig:
        held = await open_raw(rig, 3)
        reader, writer = await asyncio.open_connection("127.0.0.1", rig.server.port)
        writer.write(CHALLENGE_REQUEST)
        assert await aborted(reader)
        for _, w in held:
            w.close()


@run
async def test_freed_connection_slot_can_be_used_again(tmp_path, monkeypatch):
    monkeypatch.setattr(server_module, "CONNECTIONS_TOTAL", 2)
    async with make_rig(tmp_path) as rig:
        held = await open_raw(rig, 2)
        held[0][1].close()
        await asyncio.sleep(0.1)
        assert (await exchange(rig, CHALLENGE_THEN_CLOSE)).startswith(b"HTTP/1.1 200")
        held[1][1].close()


@run
async def test_refused_source_gets_nothing_for_expect_continue_or_a_malformed_request(tmp_path, monkeypatch):
    async with make_rig(tmp_path) as rig:
        monkeypatch.setattr(server_module, "is_allowed_source", lambda address: False)
        expect = b"POST /v1/cmd HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n"
        assert await exchange(rig, expect) == b""
        assert await exchange(rig, b"GARBAGE\r\n\r\n") == b""
        assert await exchange(rig, b"POST /v1/cmd HTTP/1.1\r\nHost: x\r\nExpect: nonsense\r\n\r\n") == b""


@run
async def test_slow_body_ends_the_connection_without_an_answer(tmp_path, monkeypatch):
    monkeypatch.setattr(server_module, "BODY_TIMEOUT_S", 0.2)
    async with make_rig(tmp_path) as rig:
        slow = b"POST /v1/cmd HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabcde"
        assert await exchange(rig, slow, wait=3.0) == b""


@run
async def test_responses_carry_no_server_header(tmp_path):
    async with make_rig(tmp_path) as rig:
        async with rig.http.post(rig.url("/v1/challenge")) as response:
            assert "Server" not in response.headers
        async with rig.http.post(rig.url("/nowhere")) as response:
            assert response.status == 404 and "Server" not in response.headers
        ws = await rig.http.ws_connect(rig.url("/v1/ws", "ws"))
        assert "Server" not in ws._response.headers
        await ws.close()


# Logs

@run
async def test_malformed_requests_write_nothing_to_the_plugin_log(tmp_path):
    async with make_rig(tmp_path) as rig:
        before = len(rig.records)
        assert b" 400 " in await exchange(rig, b"GARBAGE\r\n\r\n")
        assert await exchange(rig, b"GET / HTTP/9.9\r\nHost: x\r\n\r\n")
        await asyncio.sleep(0.05)
        assert len(rig.records) == before


@run
async def test_rejections_log_at_debug_and_one_counted_summary_a_minute(tmp_path):
    async with make_rig(tmp_path) as rig:
        phone = HttpPhone(rig, await pair(rig))
        first = len(rig.records)
        for _ in range(10):
            assert (await phone.plain(b"short"))[0] == 400
        rejected = [r for r in rig.records[first:] if "rejected" in r.getMessage()]
        assert len(rejected) == 10 and {r.levelno for r in rejected} == {logging.DEBUG}
        rig.clock.advance(60_000)
        await phone.plain(b"short")
        summaries = [r for r in rig.records[first:] if r.levelno == logging.INFO and "rejected" in r.getMessage()]
        assert [r.getMessage() for r in summaries] == ["messages rejected since the last summary: bad_message=11"]
        await phone.plain(b"short")
        assert len([r for r in rig.records[first:] if r.levelno == logging.INFO and "rejected" in r.getMessage()]) == 1


@run
async def test_socket_lines_carry_no_address(tmp_path):
    async with make_rig(tmp_path) as rig:
        stream = await StreamPhone.connect(rig, await pair(rig))
        await stream.ws.close()
        await until(lambda: any("stream closed" in r.getMessage() for r in rig.records))
        assert not any("127.0.0.1" in r.getMessage() for r in rig.records)


# Challenges

@run
async def test_challenges_are_limited_per_address_each_second_over_http(tmp_path):
    async with make_rig(tmp_path) as rig:
        for _ in range(16):
            async with rig.http.post(rig.url("/v1/challenge")) as response:
                assert response.status == 200
        async with rig.http.post(rig.url("/v1/challenge")) as response:
            assert (response.status, await response.json()) == (429, {"error": "rate_limited"})
        rig.clock.advance(1000)
        async with rig.http.post(rig.url("/v1/challenge")) as response:
            assert response.status == 200


@run
async def test_challenges_are_limited_per_address_each_second_over_the_stream(tmp_path):
    async with make_rig(tmp_path) as rig:
        stream = await StreamPhone.connect(rig, await pair(rig))  # the first challenge came with the connection
        for _ in range(15):
            await stream.get_challenge()
        await stream.ws.send_str('{"type":"challenge"}')
        assert await stream.text() == {"type": "error", "error": "rate_limited"}
        rig.clock.advance(1000)
        assert await stream.get_challenge()


@run
async def test_challenge_request_with_a_body_is_refused(tmp_path):
    async with make_rig(tmp_path) as rig:
        async with rig.http.post(rig.url("/v1/challenge"), data=b"x") as response:
            assert (response.status, await response.json()) == (413, {"error": "bad_message"})

        async def chunks():
            yield b"abc"

        async with rig.http.post(rig.url("/v1/challenge"), data=chunks()) as response:
            assert response.status == 413


# Sender cleanup

@run
async def test_sender_registered_by_a_refused_message_is_dropped_when_the_socket_closes(tmp_path):
    async with make_rig(tmp_path) as rig:
        stream = await StreamPhone.connect(rig, await pair(rig))
        assert await stream.ask({"type": "press", "key": 0x66, "mods": 0}) == stream.error("unsupported_key")
        assert len(rig.server._receiver.senders) == 1
        await stream.ws.close()
        await until(lambda: not rig.server._receiver.senders)


# Pending key-file write

@run
async def test_removal_error_stays_until_the_pending_write_succeeds(tmp_path, monkeypatch):
    state = {"pending": False, "fixed": False}
    monkeypatch.setattr(DeviceStore, "write_pending", property(lambda self: state["pending"]))

    def retry(self):
        if state["fixed"]:
            state["pending"] = False
        return not state["pending"]

    monkeypatch.setattr(DeviceStore, "retry_write", retry)
    monkeypatch.setattr(server_module, "WRITE_RETRY_S", 0.05)
    async with make_rig(tmp_path) as rig:
        paired = await pair(rig)

        def broken(*args):
            state["pending"] = True
            raise StoreError("disk")

        monkeypatch.setattr(rig.store, "_write", broken)
        assert (await rig.server.remove_device(paired.device_id.hex()))["error"] == server_module.STORAGE_ERROR
        assert rig.server.start_pairing()["error"] == server_module.STORAGE_ERROR
        await asyncio.sleep(0.2)  # several retries, all failing
        assert rig.server.state()["error"] == server_module.STORAGE_ERROR
        state["fixed"] = True
        await until(lambda: rig.server.state()["error"] is None)
        assert rig.server.start_pairing()["error"] is None
