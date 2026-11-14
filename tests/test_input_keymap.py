# Tests for the HID usage and ASCII character maps.
import string

import pytest

from hotbar.input.keymap import (
    ALL_KEY_CODES,
    MODIFIER_EVDEV,
    char_supported,
    evdev_for_usage,
    key_for_char,
    key_supported,
)

KNOWN_USAGES = {
    0x04: 30,  # A
    0x1D: 44,  # Z
    0x1E: 2,  # 1
    0x27: 11,  # 0
    0x28: 28,  # Enter
    0x29: 1,  # Esc
    0x2A: 14,  # Backspace
    0x2B: 15,  # Tab
    0x2C: 57,  # Space
    0x31: 43,  # backslash
    0x32: 43,  # non-US # maps to backslash as the kernel does
    0x39: 58,  # CapsLock
    0x3A: 59,  # F1
    0x45: 88,  # F12
    0x46: 99,  # PrintScreen
    0x48: 119,  # Pause
    0x49: 110,  # Insert
    0x4A: 102,  # Home
    0x4C: 111,  # Delete
    0x4F: 106,  # Right
    0x50: 105,  # Left
    0x51: 108,  # Down
    0x52: 103,  # Up
    0x53: 69,  # NumLock
    0x58: 96,  # keypad Enter
    0x59: 79,  # keypad 1
    0x62: 82,  # keypad 0
    0x64: 86,  # 102nd key
    0x65: 127,  # Compose
    0x68: 183,  # F13
    0x73: 194,  # F24
    0x7F: 113,  # Mute
    0x80: 115,  # Volume Up
    0x81: 114,  # Volume Down
}


def test_modifier_order_matches_the_hid_boot_report():
    # LCtrl, LShift, LAlt, LGUI, RCtrl, RShift, RAlt, RGUI
    assert MODIFIER_EVDEV == (29, 42, 56, 125, 97, 54, 100, 126)


@pytest.mark.parametrize(("usage", "code"), KNOWN_USAGES.items())
def test_known_usages(usage, code):
    assert evdev_for_usage(usage) == code
    assert key_supported(usage)


@pytest.mark.parametrize("usage", [*range(0x00, 0x04), *range(0xE0, 0xE8)])
def test_reserved_and_modifier_usages_are_not_keys(usage):
    assert evdev_for_usage(usage) is None
    assert not key_supported(usage)


@pytest.mark.parametrize("usage", [-1, 0x66, 0x82, 0xFF, 0x100, 0x10000])
def test_other_unmapped_usages(usage):
    assert evdev_for_usage(usage) is None
    assert not key_supported(usage)


def test_the_whole_range_is_consistent():
    mapped = {usage: evdev_for_usage(usage) for usage in range(0x100)}
    assert all(key_supported(u) == (c is not None) for u, c in mapped.items())
    # Letters, digits and the F-keys are all present.
    for usage in [*range(0x04, 0x66), *range(0x68, 0x74)]:
        assert mapped[usage] is not None, hex(usage)


def test_no_key_maps_onto_a_modifier_code():
    codes = {evdev_for_usage(u) for u in range(0x100)} - {None}
    assert codes.isdisjoint(MODIFIER_EVDEV)


def test_all_key_codes_cover_table_modifiers_and_characters():
    table = {evdev_for_usage(u) for u in range(0x100)} - {None}
    assert ALL_KEY_CODES == table | set(MODIFIER_EVDEV)
    for ch in map(chr, range(0x20, 0x7F)):
        assert key_for_char(ch)[0] in ALL_KEY_CODES


def test_spot_checked_characters():
    assert key_for_char("a") == (30, False)
    assert key_for_char("A") == (30, True)
    assert key_for_char("!") == (2, True)
    assert key_for_char("1") == (2, False)
    assert key_for_char("0") == (11, False)
    assert key_for_char(")") == (11, True)
    assert key_for_char(" ") == (57, False)


def test_letters_follow_the_qwerty_rows():
    for row, first in (("qwertyuiop", 16), ("asdfghjkl", 30), ("zxcvbnm", 44)):
        for offset, letter in enumerate(row):
            assert key_for_char(letter) == (first + offset, False)
            assert key_for_char(letter.upper()) == (first + offset, True)


def test_digits_and_their_shifted_symbols():
    for offset, (digit, symbol) in enumerate(zip("1234567890", "!@#$%^&*()")):
        assert key_for_char(digit) == (2 + offset, False)
        assert key_for_char(symbol) == (2 + offset, True)


def test_punctuation_pairs():
    expected = {
        "-": (12, False), "_": (12, True),
        "=": (13, False), "+": (13, True),
        "[": (26, False), "{": (26, True),
        "]": (27, False), "}": (27, True),
        "\\": (43, False), "|": (43, True),
        ";": (39, False), ":": (39, True),
        "'": (40, False), '"': (40, True),
        "`": (41, False), "~": (41, True),
        ",": (51, False), "<": (51, True),
        ".": (52, False), ">": (52, True),
        "/": (53, False), "?": (53, True),
    }
    for ch, mapped in expected.items():
        assert key_for_char(ch) == mapped, ch


def test_every_printable_ascii_character_maps_to_its_own_key_and_shift_state():
    printable = [chr(c) for c in range(0x20, 0x7F)]
    assert len(printable) == 95
    mapped = [key_for_char(ch) for ch in printable]
    assert all(m is not None for m in mapped)
    assert len(set(mapped)) == 95
    assert all(char_supported(ch) for ch in printable)
    assert set(string.printable) - set(printable) == set("\t\n\r\x0b\x0c")


@pytest.mark.parametrize("ch", ["é", "\n", "\t", "\x7f", "\x1f", "€", "😀", "", "ab"])
def test_other_characters_are_unsupported(ch):
    assert key_for_char(ch) is None
    assert not char_supported(ch)
