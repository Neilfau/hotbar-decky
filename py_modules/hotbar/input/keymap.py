# Static maps from USB HID keyboard usages and ASCII characters to Linux evdev key codes.
import string

# Modifier bits 0..7 of a USB HID boot report, as evdev codes:
# LCtrl, LShift, LAlt, LGUI, RCtrl, RShift, RAlt, RGUI.
KEY_LEFTCTRL = 29
KEY_LEFTSHIFT = 42
KEY_LEFTALT = 56
KEY_LEFTMETA = 125
KEY_RIGHTCTRL = 97
KEY_RIGHTSHIFT = 54
KEY_RIGHTALT = 100
KEY_RIGHTMETA = 126
MODIFIER_EVDEV: tuple[int, ...] = (
    KEY_LEFTCTRL,
    KEY_LEFTSHIFT,
    KEY_LEFTALT,
    KEY_LEFTMETA,
    KEY_RIGHTCTRL,
    KEY_RIGHTSHIFT,
    KEY_RIGHTALT,
    KEY_RIGHTMETA,
)

# HID keyboard-page usage -> evdev code, the same mapping the kernel HID driver uses.
# Usages 0xE0..0xE7 (the modifiers) are deliberately absent: a modifier is never a key.
# 0x66 (Power) is left out on purpose so that a key from the phone cannot suspend the device.
_USAGE_TO_EVDEV: dict[int, int] = {
    # Letters A..Z.
    0x04: 30, 0x05: 48, 0x06: 46, 0x07: 32, 0x08: 18, 0x09: 33, 0x0A: 34, 0x0B: 35,
    0x0C: 23, 0x0D: 36, 0x0E: 37, 0x0F: 38, 0x10: 50, 0x11: 49, 0x12: 24, 0x13: 25,
    0x14: 16, 0x15: 19, 0x16: 31, 0x17: 20, 0x18: 22, 0x19: 47, 0x1A: 17, 0x1B: 45,
    0x1C: 21, 0x1D: 44,
    # Digits 1..9, 0.
    0x1E: 2, 0x1F: 3, 0x20: 4, 0x21: 5, 0x22: 6, 0x23: 7, 0x24: 8, 0x25: 9,
    0x26: 10, 0x27: 11,
    # Enter, Esc, Backspace, Tab, Space, - = [ ] \ and the non-US # key (backslash, as the kernel does).
    0x28: 28, 0x29: 1, 0x2A: 14, 0x2B: 15, 0x2C: 57, 0x2D: 12, 0x2E: 13, 0x2F: 26,
    0x30: 27, 0x31: 43, 0x32: 43,
    # ; ' ` , . /, then CapsLock and F1..F12.
    0x33: 39, 0x34: 40, 0x35: 41, 0x36: 51, 0x37: 52, 0x38: 53, 0x39: 58,
    0x3A: 59, 0x3B: 60, 0x3C: 61, 0x3D: 62, 0x3E: 63, 0x3F: 64, 0x40: 65, 0x41: 66,
    0x42: 67, 0x43: 68, 0x44: 87, 0x45: 88,
    # PrintScreen (SysRq), ScrollLock, Pause, Insert, Home, PageUp, Delete, End, PageDown.
    0x46: 99, 0x47: 70, 0x48: 119, 0x49: 110, 0x4A: 102, 0x4B: 104, 0x4C: 111,
    0x4D: 107, 0x4E: 109,
    # Right, Left, Down, Up arrows.
    0x4F: 106, 0x50: 105, 0x51: 108, 0x52: 103,
    # NumLock and the keypad: / * - + Enter 1..9 0 .
    0x53: 69, 0x54: 98, 0x55: 55, 0x56: 74, 0x57: 78, 0x58: 96, 0x59: 79, 0x5A: 80,
    0x5B: 81, 0x5C: 75, 0x5D: 76, 0x5E: 77, 0x5F: 71, 0x60: 72, 0x61: 73, 0x62: 82,
    0x63: 83,
    # 102nd key, Compose (the menu key), keypad =.
    0x64: 86, 0x65: 127, 0x67: 117,
    # F13..F24.
    0x68: 183, 0x69: 184, 0x6A: 185, 0x6B: 186, 0x6C: 187, 0x6D: 188, 0x6E: 189,
    0x6F: 190, 0x70: 191, 0x71: 192, 0x72: 193, 0x73: 194,
    # Open, Help, Menu (props), Select (front), Stop, Again, Undo, Cut, Copy, Paste, Find.
    0x74: 134, 0x75: 138, 0x76: 130, 0x77: 132, 0x78: 128, 0x79: 129, 0x7A: 131,
    0x7B: 137, 0x7C: 133, 0x7D: 135, 0x7E: 136,
    # Mute, Volume Up, Volume Down.
    0x7F: 113, 0x80: 115, 0x81: 114,
    # Keypad comma, International 1..6 (ro, katakana/hiragana, yen, henkan, muhenkan, keypad jp comma).
    0x85: 121, 0x87: 89, 0x88: 93, 0x89: 124, 0x8A: 92, 0x8B: 94, 0x8C: 95,
    # Lang 1..5 (hangeul, hanja, katakana, hiragana, zenkaku/hankaku).
    0x90: 122, 0x91: 123, 0x92: 90, 0x93: 91, 0x94: 85,
}

# Punctuation keys on a US QWERTY layout: usage -> (unshifted, shifted).
_PUNCTUATION = {
    0x2D: "-_", 0x2E: "=+", 0x2F: "[{", 0x30: "]}", 0x31: "\\|",
    0x33: ";:", 0x34: "'\"", 0x35: "`~", 0x36: ",<", 0x37: ".>", 0x38: "/?",
}


def _build_char_keys() -> dict[str, tuple[int, bool]]:
    chars = {" ": (_USAGE_TO_EVDEV[0x2C], False)}
    for offset, letter in enumerate(string.ascii_lowercase):
        code = _USAGE_TO_EVDEV[0x04 + offset]
        chars[letter] = (code, False)
        chars[letter.upper()] = (code, True)
    for offset, (plain, shifted) in enumerate(zip("1234567890", "!@#$%^&*()")):
        code = _USAGE_TO_EVDEV[0x1E + offset]
        chars[plain] = (code, False)
        chars[shifted] = (code, True)
    for usage, (plain, shifted) in _PUNCTUATION.items():
        code = _USAGE_TO_EVDEV[usage]
        chars[plain] = (code, False)
        chars[shifted] = (code, True)
    return chars


_CHAR_TO_KEY = _build_char_keys()

# Every key code the keyboard device has to declare.
ALL_KEY_CODES: frozenset[int] = frozenset(_USAGE_TO_EVDEV.values()) | frozenset(MODIFIER_EVDEV)


def evdev_for_usage(usage: int) -> int | None:
    return _USAGE_TO_EVDEV.get(usage)


def key_for_char(ch: str) -> tuple[int, bool] | None:
    """Return (evdev code, needs Shift) for one printable ASCII character, else None."""
    return _CHAR_TO_KEY.get(ch)


def key_supported(usage: int) -> bool:
    return usage in _USAGE_TO_EVDEV


def char_supported(ch: str) -> bool:
    return ch in _CHAR_TO_KEY
