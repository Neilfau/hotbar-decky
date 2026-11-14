# Turns validated key, text, pointer and scroll commands into evdev events, one action at a time.
import asyncio
from collections.abc import Awaitable, Callable, Hashable, Sequence
from contextlib import suppress
from functools import partial

from ..constants import ENTER_USAGE
from .device import (
    EV_KEY,
    EV_REL,
    EV_SYN,
    SYN_REPORT,
    Event,
    InputDevice,
    InputError,
    UInputDevice,
)
from .keymap import (
    ALL_KEY_CODES,
    KEY_LEFTSHIFT,
    MODIFIER_EVDEV,
    evdev_for_usage,
    key_for_char,
)

PRESS_HOLD_S = 0.02
CHAR_HOLD_S = 0.002
CHAR_GAP_S = 0.002
SETTLE_S = 0.02  # after the open combo, and before the submit Enter

HI_RES_PER_NOTCH = 120

REL_X = 0x00
REL_Y = 0x01
REL_HWHEEL = 0x06
REL_WHEEL = 0x08
REL_WHEEL_HI_RES = 0x0B
REL_HWHEEL_HI_RES = 0x0C
BTN_LEFT = 0x110
BTN_RIGHT = 0x111

_BUTTONS = {"left": BTN_LEFT, "right": BTN_RIGHT}
_SYN: Event = (EV_SYN, SYN_REPORT, 0)


def _modifier_codes(mods: int) -> list[int]:
    if not 0 <= mods <= 0xFF:
        raise ValueError("modifier mask out of range")
    return [code for bit, code in enumerate(MODIFIER_EVDEV) if mods >> bit & 1]


def _key_code(usage: int) -> int:
    code = evdev_for_usage(usage)
    if code is None:
        raise ValueError("unsupported key")
    return code


def _split_notches(remainder: int, amount: int) -> tuple[int, int]:
    """Add amount to the remainder; return whole notches (truncated toward zero) and what is left."""
    total = remainder + amount
    notches = abs(total) // HI_RES_PER_NOTCH
    if total < 0:
        notches = -notches
    return notches, total - notches * HI_RES_PER_NOTCH


_ENTER_CODE = _key_code(ENTER_USAGE)


class Injector:
    """Writes input events to a keyboard and a pointer device. Every public method takes one lock,
    so the parts of one action are never split by another. Nothing here logs: keys, text and
    pointer data must not reach a log."""

    def __init__(
        self,
        keyboard: InputDevice,
        pointer: InputDevice,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._keyboard = keyboard
        self._pointer = pointer
        self._sleep = sleep
        self._lock = asyncio.Lock()
        self._down: list[int] = []  # keyboard codes believed down, in press order
        self._holders: dict[str, Hashable] = {}  # pointer button -> the owner that pressed it
        self._wheel_rem = 0
        self._hwheel_rem = 0

    @classmethod
    def open_uinput(cls) -> "Injector":
        keyboard = UInputDevice("HotBar Keyboard", keys=ALL_KEY_CODES)
        try:
            pointer = UInputDevice(
                "HotBar Pointer",
                keys=(BTN_LEFT, BTN_RIGHT),
                rel_axes=(REL_X, REL_Y, REL_WHEEL, REL_HWHEEL, REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES),
            )
        except InputError:
            keyboard.close()
            raise
        return cls(keyboard, pointer)

    async def press(self, key: int, mods: int) -> None:
        code = _key_code(key)
        mod_codes = _modifier_codes(mods)
        async with self._lock:
            await self._combo(code, mod_codes, PRESS_HOLD_S)

    async def type_text(self, text: str, open: tuple[int, int] | None, submit: bool) -> None:
        # Everything is checked before the first event so that a bad request writes nothing.
        taps = []
        for ch in text:
            tap = key_for_char(ch)
            if tap is None:
                raise ValueError("unsupported character")
            taps.append(tap)
        open_combo = None
        if open is not None:
            open_combo = (_key_code(open[0]), _modifier_codes(open[1]))

        async with self._lock:
            if open_combo is not None:
                await self._combo(*open_combo, PRESS_HOLD_S)
                await self._sleep(SETTLE_S)
            for index, (code, shift) in enumerate(taps):
                if index:
                    await self._sleep(CHAR_GAP_S)
                await self._combo(code, [KEY_LEFTSHIFT] if shift else [], CHAR_HOLD_S)
            if submit:
                await self._sleep(SETTLE_S)
                await self._combo(_ENTER_CODE, [], PRESS_HOLD_S)

    async def move(self, dx: int, dy: int) -> None:
        events: list[Event] = []
        if dx:
            events.append((EV_REL, REL_X, dx))
        if dy:
            events.append((EV_REL, REL_Y, dy))
        if not events:
            return
        events.append(_SYN)
        async with self._lock:
            self._emit(self._pointer, events)

    async def scroll(self, dx: int, dy: int) -> None:
        """Scroll in 1/120-notch units. A positive dy scrolls up, a positive dx scrolls right.
        The high-resolution axes carry every unit, the legacy axes only whole notches."""
        if not dx and not dy:
            return
        async with self._lock:
            events: list[Event] = []
            wheel_rem, hwheel_rem = self._wheel_rem, self._hwheel_rem
            if dy:
                notches, wheel_rem = _split_notches(wheel_rem, dy)
                events.append((EV_REL, REL_WHEEL_HI_RES, dy))
                if notches:
                    events.append((EV_REL, REL_WHEEL, notches))
            if dx:
                notches, hwheel_rem = _split_notches(hwheel_rem, dx)
                events.append((EV_REL, REL_HWHEEL_HI_RES, dx))
                if notches:
                    events.append((EV_REL, REL_HWHEEL, notches))
            events.append(_SYN)
            self._emit(self._pointer, events)
            self._wheel_rem, self._hwheel_rem = wheel_rem, hwheel_rem

    async def button(self, owner: Hashable, button: str, down: bool) -> None:
        code = _BUTTONS.get(button)
        if code is None:
            raise ValueError("unsupported button")
        async with self._lock:
            if down:
                # Recorded before the write: if the write fails midway the button may be down.
                self._holders[button] = owner
            self._emit(self._pointer, [(EV_KEY, code, int(down)), _SYN])
            if not down:
                self._holders.pop(button, None)

    async def release_owner(self, owner: Hashable) -> None:
        async with self._lock:
            held = [button for button, holder in self._holders.items() if holder == owner]
            self._run_all(*(partial(self._release_button, button) for button in held))

    async def release_all(self) -> None:
        async with self._lock:
            self._release_everything()

    def close(self) -> None:
        """Release what is still held as far as possible, then close both devices. Never raises."""
        try:
            with suppress(InputError):
                self._release_everything()
        finally:
            try:
                self._keyboard.close()
            finally:
                self._pointer.close()

    async def _combo(self, code: int, mod_codes: Sequence[int], hold: float) -> None:
        """Modifiers down, key down, hold, key up, modifiers up (reverse). The lock must be held."""
        try:
            if mod_codes:
                self._keys_down(mod_codes)
            self._keys_down([code])
            await self._sleep(hold)
            self._keys_up([code])
            if mod_codes:
                self._keys_up(reversed(mod_codes))
        finally:
            # Also runs on cancellation: it must not await, and a failing device must not hide the
            # error that is already on its way out.
            with suppress(InputError):
                self._release_keys()

    def _keys_down(self, codes: Sequence[int]) -> None:
        # Recorded before the write: if the write fails midway the keys may be down.
        self._down.extend(codes)
        self._emit(self._keyboard, [(EV_KEY, code, 1) for code in codes] + [_SYN])

    def _keys_up(self, codes: Sequence[int]) -> None:
        codes = list(codes)
        self._emit(self._keyboard, [(EV_KEY, code, 0) for code in codes] + [_SYN])
        for code in codes:
            self._down.remove(code)

    def _release_keys(self) -> None:
        if self._down:
            self._keys_up(list(reversed(self._down)))

    def _release_button(self, button: str) -> None:
        self._emit(self._pointer, [(EV_KEY, _BUTTONS[button], 0), _SYN])
        self._holders.pop(button, None)

    def _release_everything(self) -> None:
        self._run_all(
            self._release_keys,
            *(partial(self._release_button, button) for button in list(self._holders)),
        )

    @staticmethod
    def _run_all(*steps: Callable[[], None]) -> None:
        """Run every step even if one fails, then raise the first failure."""
        first: InputError | None = None
        for step in steps:
            try:
                step()
            except InputError as e:
                if first is None:
                    first = e
        if first is not None:
            raise first

    @staticmethod
    def _emit(device: InputDevice, events: Sequence[Event]) -> None:
        try:
            device.write(events)
        except OSError as e:
            raise InputError(f"input write failed: {e}") from e
