# Tests for the injector: exact event sequences on fake devices, failure cleanup and locking.
import asyncio
import threading
import time

import pytest

from hotbar.input import injector as injector_module
from hotbar.input.device import FakeDevice, InputError
from hotbar.input.injector import Injector

SYN = (0, 0, 0)
LCTRL, LSHIFT = 29, 42
KEY_A, KEY_B, KEY_1, KEY_ENTER = 30, 48, 2, 28
BTN_LEFT, BTN_RIGHT = 0x110, 0x111
REL_X, REL_Y, REL_HWHEEL, REL_WHEEL, REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES = 0, 1, 6, 8, 11, 12
USAGE_A, USAGE_ENTER, USAGE_SPACE = 0x04, 0x28, 0x2C


def down(code):
    return (1, code, 1)


def up(code):
    return (1, code, 0)


class FailOnWrite(FakeDevice):
    """Fails the write calls whose 1-based numbers are given; every other write succeeds."""

    def __init__(self, *fail_on):
        super().__init__()
        self.fail_on = set(fail_on)
        self.writes = 0

    def write(self, events):
        self.writes += 1
        if self.writes in self.fail_on:
            raise OSError("boom")
        super().write(events)


class Rig:
    def __init__(self, keyboard=None, pointer=None, sleep=None, hold=None):
        self.kb = keyboard or FakeDevice()
        self.ptr = pointer or FakeDevice()
        self.sleeps = []
        self.inj = Injector(self.kb, self.ptr, sleep=sleep or self.fake_sleep, hold=hold or self.fake_hold)

    def fake_hold(self, stop, seconds):
        self.sleeps.append(seconds)

    async def fake_sleep(self, seconds):
        self.sleeps.append(seconds)
        await asyncio.sleep(0)  # a real suspension point, so other tasks get a chance to run


def run(coro):
    return asyncio.run(coro)


# --- press ---------------------------------------------------------------------------------


def test_press_without_modifiers():
    rig = Rig()
    run(rig.inj.press(USAGE_A, 0))
    assert rig.kb.events == [down(KEY_A), SYN, up(KEY_A), SYN]
    assert rig.ptr.events == []
    assert rig.sleeps == [0.02]


def test_press_with_two_modifiers_releases_in_reverse_order():
    rig = Rig()
    run(rig.inj.press(USAGE_A, 0b11))  # LCtrl + LShift
    assert rig.kb.events == [
        down(LCTRL), down(LSHIFT), SYN,
        down(KEY_A), SYN,
        up(KEY_A), SYN,
        up(LSHIFT), up(LCTRL), SYN,
    ]


def test_press_uses_every_modifier_bit_in_order():
    rig = Rig()
    run(rig.inj.press(USAGE_A, 0xFF))
    mods = (29, 42, 56, 125, 97, 54, 100, 126)
    assert rig.kb.events == [
        *[down(m) for m in mods], SYN,
        down(KEY_A), SYN,
        up(KEY_A), SYN,
        *[up(m) for m in reversed(mods)], SYN,
    ]


@pytest.mark.parametrize(("key", "mods"), [(0x01, 0), (0xE0, 0), (0x00, 0), (0x66, 0), (USAGE_A, 256), (USAGE_A, -1)])
def test_press_rejects_bad_input_before_writing(key, mods):
    rig = Rig()
    with pytest.raises(ValueError):
        run(rig.inj.press(key, mods))
    assert rig.kb.events == []
    assert rig.sleeps == []


# --- type_text -----------------------------------------------------------------------------


def test_type_text_plain_lowercase():
    rig = Rig()
    run(rig.inj.type_text("ab", None, False))
    assert rig.kb.events == [
        down(KEY_A), SYN, up(KEY_A), SYN,
        down(KEY_B), SYN, up(KEY_B), SYN,
    ]
    assert rig.sleeps == [0.002, 0.002, 0.002]  # hold, gap, hold


def test_type_text_shifts_uppercase_and_shifted_symbols():
    rig = Rig()
    run(rig.inj.type_text("A!a", None, False))
    assert rig.kb.events == [
        down(LSHIFT), SYN, down(KEY_A), SYN, up(KEY_A), SYN, up(LSHIFT), SYN,
        down(LSHIFT), SYN, down(KEY_1), SYN, up(KEY_1), SYN, up(LSHIFT), SYN,
        down(KEY_A), SYN, up(KEY_A), SYN,
    ]


def test_type_text_space_and_digits():
    rig = Rig()
    run(rig.inj.type_text("1 ", None, False))
    assert rig.kb.events == [down(KEY_1), SYN, up(KEY_1), SYN, down(57), SYN, up(57), SYN]


def test_type_text_with_open_combo():
    rig = Rig()
    run(rig.inj.type_text("a", (USAGE_SPACE, 0b1), False))  # LCtrl+Space, then "a"
    assert rig.kb.events == [
        down(LCTRL), SYN, down(57), SYN, up(57), SYN, up(LCTRL), SYN,
        down(KEY_A), SYN, up(KEY_A), SYN,
    ]
    assert rig.sleeps == [0.02, 0.02, 0.002]  # open hold, settle, character hold


def test_type_text_with_submit():
    rig = Rig()
    run(rig.inj.type_text("a", None, True))
    assert rig.kb.events == [
        down(KEY_A), SYN, up(KEY_A), SYN,
        down(KEY_ENTER), SYN, up(KEY_ENTER), SYN,
    ]
    assert rig.sleeps == [0.002, 0.02, 0.02]  # character hold, settle, Enter hold


def test_type_text_with_open_and_submit():
    rig = Rig()
    run(rig.inj.type_text("ab", (USAGE_SPACE, 0), True))
    assert rig.kb.events == [
        down(57), SYN, up(57), SYN,
        down(KEY_A), SYN, up(KEY_A), SYN,
        down(KEY_B), SYN, up(KEY_B), SYN,
        down(KEY_ENTER), SYN, up(KEY_ENTER), SYN,
    ]
    assert rig.sleeps == [0.02, 0.02, 0.002, 0.002, 0.002, 0.02, 0.02]


def test_type_text_never_infers_a_submit_from_the_text():
    rig = Rig()
    with pytest.raises(ValueError):
        run(rig.inj.type_text("a\n", None, False))
    run(rig.inj.type_text("a", None, False))
    assert KEY_ENTER not in [e[1] for e in rig.kb.events]


def test_type_text_with_nothing_to_do_writes_nothing():
    rig = Rig()
    run(rig.inj.type_text("", None, False))
    assert rig.kb.events == []


@pytest.mark.parametrize(
    ("text", "open_"),
    [
        ("héllo", None),
        ("ok\n", None),
        ("tab\there", None),
        ("ok", (0x01, 0)),  # unmapped key
        ("ok", (0xE0, 0)),  # a modifier is never a key
        ("ok", (USAGE_A, 256)),
        ("emoji 😀", (USAGE_A, 0)),
    ],
)
def test_type_text_rejects_everything_before_the_first_event(text, open_):
    rig = Rig()
    with pytest.raises(ValueError):
        run(rig.inj.type_text(text, open_, True))
    assert rig.kb.events == []
    assert rig.ptr.events == []
    assert rig.sleeps == []


def test_type_text_error_messages_do_not_echo_the_content():
    rig = Rig()
    with pytest.raises(ValueError) as info:
        run(rig.inj.type_text("hunter2é", None, False))
    assert "é" not in str(info.value) and "hunter2" not in str(info.value)


def test_a_512_character_line_sleeps_well_under_three_seconds():
    rig = Rig()
    text = ("Hello, World! 0123456789 " * 25)[:512]
    assert len(text) == 512
    run(rig.inj.type_text(text, (USAGE_SPACE, 0b1), True))
    assert 0 < sum(rig.sleeps) < 3
    assert rig.kb.events.count(up(KEY_ENTER)) == 1
    downs = [e for e in rig.kb.events if e[2] == 1]
    ups = [e for e in rig.kb.events if e[2] == 0 and e[0] == 1]
    assert len(downs) == len(ups)


# --- pointer -------------------------------------------------------------------------------


def test_move_both_axes_one_write():
    rig = Rig()
    run(rig.inj.move(5, -7))
    assert rig.ptr.events == [(2, REL_X, 5), (2, REL_Y, -7), SYN]
    assert rig.kb.events == []


def test_move_single_axis_omits_the_zero_axis():
    rig = Rig()
    run(rig.inj.move(0, 3))
    run(rig.inj.move(-4, 0))
    assert rig.ptr.events == [(2, REL_Y, 3), SYN, (2, REL_X, -4), SYN]


def test_move_zero_writes_nothing():
    rig = Rig()
    run(rig.inj.move(0, 0))
    assert rig.ptr.events == []


def test_scroll_accumulates_whole_notches_across_calls():
    rig = Rig()

    async def go():
        for dy in (50, 50, 50, -100, -60):
            await rig.inj.scroll(0, dy)

    run(go())
    assert rig.ptr.events == [
        (2, REL_WHEEL_HI_RES, 50), SYN,  # remainder 50
        (2, REL_WHEEL_HI_RES, 50), SYN,  # remainder 100
        (2, REL_WHEEL_HI_RES, 50), (2, REL_WHEEL, 1), SYN,  # 150 -> one notch, remainder 30
        (2, REL_WHEEL_HI_RES, -100), SYN,  # -70 truncates to no notch
        (2, REL_WHEEL_HI_RES, -60), (2, REL_WHEEL, -1), SYN,  # -130 -> one notch down, remainder -10
    ]


def test_scroll_several_notches_in_one_call():
    rig = Rig()
    run(rig.inj.scroll(0, 1200))
    run(rig.inj.scroll(0, -1200))
    assert rig.ptr.events == [
        (2, REL_WHEEL_HI_RES, 1200), (2, REL_WHEEL, 10), SYN,
        (2, REL_WHEEL_HI_RES, -1200), (2, REL_WHEEL, -10), SYN,
    ]


def test_scroll_positive_dy_is_positive_wheel_and_horizontal_is_separate():
    rig = Rig()

    async def go():
        await rig.inj.scroll(130, 0)
        await rig.inj.scroll(110, 60)  # horizontal 10 + 110 = 120, one notch; vertical keeps 60
        await rig.inj.scroll(120, -240)  # vertical 60 - 240 = -180, one notch down, remainder -60

    run(go())
    assert rig.ptr.events == [
        (2, REL_HWHEEL_HI_RES, 130), (2, REL_HWHEEL, 1), SYN,
        (2, REL_WHEEL_HI_RES, 60), (2, REL_HWHEEL_HI_RES, 110), (2, REL_HWHEEL, 1), SYN,
        (2, REL_WHEEL_HI_RES, -240), (2, REL_WHEEL, -1), (2, REL_HWHEEL_HI_RES, 120), (2, REL_HWHEEL, 1), SYN,
    ]


def test_scroll_zero_writes_nothing():
    rig = Rig()
    run(rig.inj.scroll(0, 0))
    assert rig.ptr.events == []


def test_scroll_keeps_its_remainder_when_the_write_fails():
    ptr = FailOnWrite(1)
    rig = Rig(pointer=ptr)

    async def go():
        with pytest.raises(InputError):
            await rig.inj.scroll(0, 100)
        await rig.inj.scroll(0, 20)

    run(go())
    assert ptr.events == [(2, REL_WHEEL_HI_RES, 20), SYN]  # the failed 100 was never delivered


def test_button_down_and_up_edges():
    rig = Rig()

    async def go():
        await rig.inj.button("a", "left", True)
        await rig.inj.button("a", "left", False)
        await rig.inj.button("a", "right", True)
        await rig.inj.button("a", "right", False)

    run(go())
    assert rig.ptr.events == [
        down(BTN_LEFT), SYN, up(BTN_LEFT), SYN,
        down(BTN_RIGHT), SYN, up(BTN_RIGHT), SYN,
    ]
    assert rig.kb.events == []


def test_button_rejects_unknown_buttons():
    rig = Rig()
    with pytest.raises(ValueError):
        run(rig.inj.button("a", "middle", True))
    assert rig.ptr.events == []


def test_button_edge_is_emitted_even_without_state_change():
    rig = Rig()

    async def go():
        await rig.inj.button("a", "left", False)
        await rig.inj.button("a", "left", True)
        await rig.inj.button("a", "left", True)

    run(go())
    assert rig.ptr.events == [up(BTN_LEFT), SYN, down(BTN_LEFT), SYN, down(BTN_LEFT), SYN]


def test_release_owner_releases_only_that_owners_buttons():
    rig = Rig()

    async def go():
        await rig.inj.button("a", "left", True)
        await rig.inj.button("b", "right", True)
        rig.ptr.events.clear()
        await rig.inj.release_owner("a")
        assert rig.ptr.events == [up(BTN_LEFT), SYN]
        rig.ptr.events.clear()
        await rig.inj.release_owner("a")  # nothing left to release
        assert rig.ptr.events == []
        await rig.inj.release_owner("b")
        assert rig.ptr.events == [up(BTN_RIGHT), SYN]

    run(go())


def test_a_later_down_replaces_the_holder_and_an_up_clears_it():
    rig = Rig()

    async def go():
        await rig.inj.button("a", "left", True)
        await rig.inj.button("b", "left", True)
        rig.ptr.events.clear()
        await rig.inj.release_owner("a")
        assert rig.ptr.events == []
        await rig.inj.release_owner("b")
        assert rig.ptr.events == [up(BTN_LEFT), SYN]
        await rig.inj.button("a", "right", True)
        await rig.inj.button("b", "right", False)
        rig.ptr.events.clear()
        await rig.inj.release_owner("a")
        assert rig.ptr.events == []

    run(go())


def test_release_all_releases_every_held_button():
    rig = Rig()

    async def go():
        await rig.inj.button("a", "left", True)
        await rig.inj.button("b", "right", True)
        rig.ptr.events.clear()
        await rig.inj.release_all()
        assert sorted(rig.ptr.events) == sorted([up(BTN_LEFT), up(BTN_RIGHT), SYN, SYN])
        rig.ptr.events.clear()
        await rig.inj.release_all()
        assert rig.ptr.events == []

    run(go())


# --- failures and cancellation -------------------------------------------------------------


def test_device_failure_mid_press_still_releases_and_raises_input_error():
    kb = FailOnWrite(2)  # mods down succeeds, key down fails
    rig = Rig(keyboard=kb)
    with pytest.raises(InputError):
        run(rig.inj.press(USAGE_A, 0b11))
    assert kb.events == [
        down(LCTRL), down(LSHIFT), SYN,
        up(KEY_A), up(LSHIFT), up(LCTRL), SYN,  # cleanup: key and modifiers, newest first
    ]


def test_device_failure_on_key_up_still_releases_the_modifiers():
    kb = FailOnWrite(3)  # the key-up write fails
    rig = Rig(keyboard=kb)
    with pytest.raises(InputError):
        run(rig.inj.press(USAGE_A, 0b1))
    assert kb.events == [
        down(LCTRL), SYN, down(KEY_A), SYN,
        up(KEY_A), up(LCTRL), SYN,
    ]


def test_device_failure_mid_text_releases_shift_and_key_and_stops_typing():
    kb = FailOnWrite(4)  # "A": shift down, key down, key up ok, shift up fails
    rig = Rig(keyboard=kb)
    with pytest.raises(InputError):
        run(rig.inj.type_text("Abc", None, False))
    assert kb.events == [
        down(LSHIFT), SYN, down(KEY_A), SYN, up(KEY_A), SYN,
        up(LSHIFT), SYN,  # cleanup
    ]


def test_failed_cleanup_leaves_keys_for_release_all_to_retry():
    kb = FailOnWrite(3, 4)  # the key-up write and the cleanup write both fail
    rig = Rig(keyboard=kb)
    with pytest.raises(InputError):
        run(rig.inj.press(USAGE_A, 0b1))
    assert kb.events == [down(LCTRL), SYN, down(KEY_A), SYN]
    run(rig.inj.release_all())
    assert kb.events[4:] == [up(KEY_A), up(LCTRL), SYN]
    run(rig.inj.release_all())
    assert len(kb.events) == 7


def test_nothing_is_down_when_the_first_write_fails():
    rig = Rig()
    rig.kb.fail = True
    with pytest.raises(InputError):
        run(rig.inj.press(USAGE_A, 0))
    rig.kb.fail = False
    run(rig.inj.release_all())  # the key was recorded before its write, so it is released to be safe
    assert rig.kb.events == [up(KEY_A), SYN]


def test_pointer_failure_is_an_input_error():
    rig = Rig()
    rig.ptr.fail = True
    with pytest.raises(InputError):
        run(rig.inj.move(1, 1))
    with pytest.raises(InputError):
        run(rig.inj.button("a", "left", True))


def test_release_all_tries_every_step_reports_the_failure_and_keeps_what_is_still_held():
    ptr = FailOnWrite(3)  # writes 1 and 2 are the downs; the release of the left button fails
    rig = Rig(pointer=ptr)

    async def go():
        await rig.inj.button("a", "left", True)
        await rig.inj.button("a", "right", True)
        with pytest.raises(InputError):
            await rig.inj.release_all()
        assert ptr.events == [down(BTN_LEFT), SYN, down(BTN_RIGHT), SYN, up(BTN_RIGHT), SYN]
        await rig.inj.release_all()  # the left button is retried
        assert ptr.events[6:] == [up(BTN_LEFT), SYN]

    run(go())


def test_cancelling_a_press_during_the_hold_releases_the_key_and_modifiers():
    async def go():
        entered = asyncio.Event()

        loop = asyncio.get_running_loop()

        def hang(stop, _seconds):
            loop.call_soon_threadsafe(entered.set)
            stop.wait(10)

        rig = Rig(hold=hang)
        task = asyncio.create_task(rig.inj.press(USAGE_A, 0b11))
        await entered.wait()
        assert rig.kb.events == [down(LCTRL), down(LSHIFT), SYN, down(KEY_A), SYN]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert rig.kb.events[5:] == [up(KEY_A), up(LSHIFT), up(LCTRL), SYN]
        # The lock was given back.
        await asyncio.wait_for(rig.inj.move(1, 0), timeout=1)
        return rig

    rig = run(go())
    assert rig.ptr.events == [(2, REL_X, 1), SYN]


def test_cancelling_type_text_between_characters_leaves_nothing_down():
    async def go():
        calls = 0
        gap_entered = asyncio.Event()

        async def sleep(seconds):
            nonlocal calls
            calls += 1
            if calls == 1:  # the gap after the first character (holds run on a worker thread)
                gap_entered.set()
                await asyncio.Event().wait()

        rig = Rig(sleep=sleep)
        task = asyncio.create_task(rig.inj.type_text("ab", None, False))
        await gap_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return rig

    rig = run(go())
    assert rig.kb.events == [down(KEY_A), SYN, up(KEY_A), SYN]


def test_the_hold_is_wall_clock_bounded_while_the_event_loop_is_blocked():
    stamps = []

    class Stamped(FakeDevice):
        def write(self, events):
            super().write(events)
            stamps.append((time.monotonic(), events[0][1:]))

    async def go():
        inj = Injector(Stamped(), FakeDevice())
        task = asyncio.create_task(inj.press(USAGE_A, 0))
        await asyncio.sleep(0.005)
        time.sleep(0.5)  # a busy loop
        await task

    run(go())
    (t_down, d), (t_up, u) = stamps[0], stamps[1]
    assert d == (KEY_A, 1) and u == (KEY_A, 0)
    assert t_up - t_down < 0.2


# --- concurrency ---------------------------------------------------------------------------


def test_concurrent_actions_never_interleave():
    async def go():
        rig = Rig()
        await asyncio.gather(
            rig.inj.type_text("ab", (USAGE_SPACE, 0b1), True),
            rig.inj.press(USAGE_A, 0b10),
            rig.inj.move(3, 4),
            rig.inj.button("a", "left", True),
        )
        return rig

    rig = run(go())
    typed = [
        down(LCTRL), SYN, down(57), SYN, up(57), SYN, up(LCTRL), SYN,
        down(KEY_A), SYN, up(KEY_A), SYN,
        down(KEY_B), SYN, up(KEY_B), SYN,
        down(KEY_ENTER), SYN, up(KEY_ENTER), SYN,
    ]
    pressed = [down(LSHIFT), SYN, down(KEY_A), SYN, up(KEY_A), SYN, up(LSHIFT), SYN]
    assert rig.kb.events == typed + pressed
    assert rig.ptr.events == [(2, REL_X, 3), (2, REL_Y, 4), SYN, down(BTN_LEFT), SYN]


# --- close and construction ----------------------------------------------------------------


def test_close_releases_held_buttons_and_keys_then_closes_both_devices():
    kb = FailOnWrite(1, 2)  # the key goes down in intent, but neither the write nor its cleanup lands
    rig = Rig(keyboard=kb)
    with pytest.raises(InputError):
        run(rig.inj.press(USAGE_A, 0))
    run(rig.inj.button("a", "left", True))
    rig.ptr.events.clear()
    rig.inj.close()
    assert kb.events == [up(KEY_A), SYN]
    assert rig.ptr.events == [up(BTN_LEFT), SYN]
    assert kb.closed and rig.ptr.closed


def test_close_closes_both_devices_even_if_releasing_fails_and_is_repeatable():
    rig = Rig()
    run(rig.inj.button("a", "left", True))
    rig.ptr.fail = True
    rig.inj.close()
    rig.inj.close()
    assert rig.kb.closed and rig.ptr.closed


def test_open_uinput_creates_the_two_devices(monkeypatch):
    created = []

    class Stub(FakeDevice):
        def __init__(self, name, keys=(), rel_axes=()):
            super().__init__()
            created.append((name, frozenset(keys), frozenset(rel_axes)))

    monkeypatch.setattr(injector_module, "UInputDevice", Stub)
    injector_module.Injector.open_uinput()
    keyboard, pointer = created
    assert keyboard[0] == "HotBar Keyboard"
    assert keyboard[1] == injector_module.ALL_KEY_CODES and keyboard[2] == frozenset()
    assert pointer == (
        "HotBar Pointer",
        frozenset({BTN_LEFT, BTN_RIGHT}),
        frozenset({REL_X, REL_Y, REL_HWHEEL, REL_WHEEL, REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES}),
    )


def test_open_uinput_closes_the_keyboard_if_the_pointer_cannot_be_created(monkeypatch):
    made = []

    def stub(name, keys=(), rel_axes=()):
        if name == "HotBar Pointer":
            raise InputError("no pointer")
        made.append(FakeDevice())
        return made[-1]

    monkeypatch.setattr(injector_module, "UInputDevice", stub)
    with pytest.raises(InputError):
        injector_module.Injector.open_uinput()
    assert made[0].closed


def test_the_package_never_logs():
    import hotbar.input.device as d
    import hotbar.input.injector as i
    import hotbar.input.keymap as k

    for module in (d, i, k):
        source = open(module.__file__).read()
        assert "import logging" not in source and "print(" not in source
