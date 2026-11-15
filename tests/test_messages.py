# Tests for body parsing, field validation and the plugin's reply body builders.
import pytest

from hotbar import messages as m

CHALLENGE = "ab" * 16


def mapped(key: int) -> bool:
    return key < 0xE0


def typeable(_char: str) -> bool:
    return True


def check(obj, key_supported=mapped, char_supported=typeable):
    return m.validate(obj, key_supported, char_supported)


def code_of(obj, key_supported=mapped, char_supported=typeable) -> str:
    with pytest.raises(m.BodyError) as caught:
        m.validate(obj, key_supported, char_supported)
    return caught.value.code


# parse_object and parse_json_object

@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"[1,2]",
        b'"text"',
        b"5",
        b"null",
        b"\xff\xfe{}",
        b"\xef\xbb\xbf{}",
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b'{"a":1,"a":2}',
        b'{"a":',
        b"[" * 5000,
        b'{"a":' * 3000,
        '{"a":"\ud800"}'.encode("utf-8", "surrogatepass"),
    ],
)
def test_parse_object_rejects_what_is_not_a_utf8_json_object(body):
    with pytest.raises(m.BodyError) as caught:
        m.parse_object(body)
    assert caught.value.code == "bad_body"


def test_parse_object_treats_a_recursion_error_as_bad_body(monkeypatch):
    def too_deep(*_args, **_kwargs):
        raise RecursionError

    monkeypatch.setattr(m.json, "loads", too_deep)
    with pytest.raises(m.BodyError) as caught:
        m.parse_object(b"{}")
    assert caught.value.code == "bad_body"


def test_parse_object_accepts_any_valid_json_encoding():
    assert m.parse_object(b' { "b" : 2 ,\n"a":"\\u00e9\xc3\xa9" } ') == {"b": 2, "a": "\u00e9\u00e9"}


@pytest.mark.parametrize("body", [b"{}", b'{"type":1}', b'{"type":null}', b'{"type":["press"]}', b'{"Type":"hello"}'])
def test_parse_json_object_needs_a_string_type(body):
    with pytest.raises(m.BodyError) as caught:
        m.parse_json_object(body)
    assert caught.value.code == "bad_body"


def test_parse_json_object_accepts_escaped_type():
    assert m.parse_json_object(b'{"type":"\\u0068ello"}') == {"type": "hello"}


def test_body_error_carries_only_the_code():
    assert str(m.BodyError("bad_body")) == "bad_body"


# structure shared by every type

def test_type_names():
    assert [cls.type_name for cls in (m.Hello, m.Press, m.TypeText, m.Move, m.Button, m.Scroll, m.Unpair)] == [
        "hello",
        "press",
        "type",
        "move",
        "button",
        "scroll",
        "unpair",
    ]


@pytest.mark.parametrize(
    "obj",
    [
        {"type": "hello"},
        {"type": "press", "key": 4, "mods": 0},
        {"type": "type", "text": "a"},
        {"type": "move", "dx": 0, "dy": 0},
        {"type": "button", "button": "left", "state": "down"},
        {"type": "scroll", "dx": 0, "dy": 0},
        {"type": "unpair"},
    ],
)
class TestEveryType:
    def test_a_well_formed_challenge_is_allowed(self, obj):
        assert type(check({**obj, "challenge": CHALLENGE})).type_name == obj["type"]

    @pytest.mark.parametrize(
        "challenge", ["AB" * 16, "ab" * 15, "ab" * 17, "g" * 32, "", 5, None, True, [CHALLENGE], " " + "a" * 31]
    )
    def test_a_malformed_challenge_is_bad_body(self, obj, challenge):
        assert code_of({**obj, "challenge": challenge}) == "bad_body"

    def test_an_unknown_field_is_bad_body(self, obj):
        assert code_of({**obj, "extra": 1}) == "bad_body"

    def test_a_malformed_challenge_beats_key_and_character_mapping(self, obj):
        assert code_of({**obj, "challenge": "xyz"}, lambda k: False, lambda ch: False) == "bad_body"


@pytest.mark.parametrize("kind", ["launch", "Press", "", "press ", "HELLO"])
def test_unknown_type(kind):
    assert code_of({"type": kind}) == "unknown_type"
    assert code_of({"type": kind, "whatever": 1}) == "unknown_type"


def test_unknown_type_wins_over_a_malformed_challenge():
    assert code_of({"type": "launch", "challenge": "nope"}) == "unknown_type"


@pytest.mark.parametrize("kind", [None, 5, ["hello"]])
def test_a_non_string_type_is_bad_body(kind):
    assert code_of({"type": kind}) == "bad_body"
    assert code_of({}) == "bad_body"


# hello and unpair

def test_hello_and_unpair():
    assert check({"type": "hello"}) == m.Hello()
    assert check({"type": "unpair"}) == m.Unpair()
    assert code_of({"type": "hello", "name": "x"}) == "bad_body"
    assert code_of({"type": "unpair", "name": "x"}) == "bad_body"


# press

def test_press_fields():
    assert check({"type": "press", "key": 4, "mods": 0}) == m.Press(4, 0)
    assert check({"type": "press", "key": 0xDF, "mods": 255}) == m.Press(0xDF, 255)


@pytest.mark.parametrize("key", [3, 0, -1, 232, 1000, 2**64])
def test_press_key_out_of_range_is_bad_body(key):
    assert code_of({"type": "press", "key": key, "mods": 0}) == "bad_body"


@pytest.mark.parametrize("mods", [256, -1, 2**64])
def test_press_mods_out_of_range_is_bad_body(mods):
    assert code_of({"type": "press", "key": 4, "mods": mods}) == "bad_body"


@pytest.mark.parametrize("value", [True, False, 4.0, 1e2, 4.5, "4", None, [4], {"a": 1}])
def test_press_fields_must_be_integers(value):
    assert code_of({"type": "press", "key": value, "mods": 0}) == "bad_body"
    assert code_of({"type": "press", "key": 4, "mods": value}) == "bad_body"


def test_press_missing_fields():
    assert code_of({"type": "press", "key": 4}) == "bad_body"
    assert code_of({"type": "press", "mods": 0}) == "bad_body"
    assert code_of({"type": "press"}) == "bad_body"


@pytest.mark.parametrize("key", [0xE0, 0xE1, 0xE7])
def test_modifier_usage_as_key_is_unsupported_even_if_the_mapping_allows_it(key):
    assert code_of({"type": "press", "key": key, "mods": 0}, lambda k: True) == "unsupported_key"


def test_unmapped_key_is_unsupported_key():
    assert code_of({"type": "press", "key": 30, "mods": 0}, lambda k: k != 30) == "unsupported_key"


def test_range_errors_beat_key_mapping():
    never = lambda k: pytest.fail("mapping consulted before structure was checked")
    assert code_of({"type": "press", "key": 3, "mods": 0}, never) == "bad_body"
    assert code_of({"type": "press", "key": 30, "mods": 256}, never) == "bad_body"


# type

def test_type_defaults():
    assert check({"type": "type", "text": "hi"}) == m.TypeText("hi", None, False)


def test_type_with_open_and_submit():
    message = check({"type": "type", "text": "hi", "open": {"key": 40, "mods": 2}, "submit": True})
    assert message == m.TypeText("hi", (40, 2), True)
    assert check({"type": "type", "text": "hi", "submit": False}).submit is False


@pytest.mark.parametrize(
    "text, ok",
    [
        ("a" * 512, True),
        ("a" * 513, False),
        ("é" * 256, True),
        ("é" * 256 + "a", False),
        ("€" * 170, True),
        ("€" * 171, False),
        ("😀" * 128, True),
        ("😀" * 129, False),
        ("", False),
    ],
)
def test_type_text_length_counts_utf8_bytes(text, ok):
    obj = {"type": "type", "text": text}
    if ok:
        assert check(obj).text == text
    else:
        assert code_of(obj) == "bad_body"


@pytest.mark.parametrize("char", ["\x00", "\n", "\r", "\t", "\x08", "\x1f", "\x7f", "\x80", "\x85", "\x9f", "\u2028", "\u2029"])
def test_type_text_forbidden_characters_are_bad_body(char):
    assert code_of({"type": "type", "text": f"a{char}b"}) == "bad_body"
    assert code_of({"type": "type", "text": char}) == "bad_body"


def test_type_text_rejects_a_lone_surrogate():
    assert code_of({"type": "type", "text": "a\ud800b"}) == "bad_body"
    assert code_of({"type": "type", "text": "\udfff"}) == "bad_body"


@pytest.mark.parametrize("text", [" ", "  padded  ", "\u00a0", "\u2060", "e\u0301", "👨‍👩‍👧", "/command", "\u2027", "\u00a1"])
def test_type_text_allows_spaces_and_unusual_printable_characters(text):
    assert check({"type": "type", "text": text}).text == text


@pytest.mark.parametrize("text", [None, 5, True, ["a"], {"a": "b"}, 1.5])
def test_type_text_must_be_a_string(text):
    assert code_of({"type": "type", "text": text}) == "bad_body"


def test_type_missing_text():
    assert code_of({"type": "type"}) == "bad_body"
    assert code_of({"type": "type", "open": {"key": 4, "mods": 0}}) == "bad_body"


@pytest.mark.parametrize("submit", ["yes", "true", 1, 0, None, [], {}])
def test_type_submit_must_be_a_boolean(submit):
    assert code_of({"type": "type", "text": "a", "submit": submit}) == "bad_body"


@pytest.mark.parametrize(
    "open_value",
    [
        None,
        [],
        "x",
        5,
        True,
        {},
        {"key": 4},
        {"mods": 0},
        {"key": 4, "mods": 0, "extra": 1},
        {"key": 3, "mods": 0},
        {"key": 232, "mods": 0},
        {"key": 4, "mods": 256},
        {"key": 4, "mods": -1},
        {"key": True, "mods": 0},
        {"key": 4.0, "mods": 0},
        {"key": 4, "mods": "0"},
        {"key": "4", "mods": 0},
    ],
)
def test_type_open_must_be_a_well_formed_combo(open_value):
    assert code_of({"type": "type", "text": "a", "open": open_value}) == "bad_body"


def test_type_open_with_a_modifier_or_unmapped_key_is_unsupported_key():
    assert code_of({"type": "type", "text": "a", "open": {"key": 225, "mods": 0}}) == "unsupported_key"
    assert code_of({"type": "type", "text": "a", "open": {"key": 30, "mods": 0}}, lambda k: k != 30) == "unsupported_key"


def test_type_with_an_untypeable_character_is_unsupported_char():
    assert code_of({"type": "type", "text": "ab"}, char_supported=lambda ch: ch != "b") == "unsupported_char"


def test_type_validation_order():
    seen = []

    def keys(k):
        seen.append("key")
        return False

    def chars(ch):
        seen.append("char")
        return False

    # structure first: bad submit hides both mapping errors, and neither mapping is consulted
    bad = {"type": "type", "text": "a", "open": {"key": 30, "mods": 0}, "submit": "x"}
    assert code_of(bad, keys, chars) == "bad_body" and seen == []
    # then the open key, then the characters
    both = {"type": "type", "text": "a", "open": {"key": 30, "mods": 0}}
    assert code_of(both, keys, chars) == "unsupported_key" and seen == ["key"]
    seen.clear()
    assert code_of({"type": "type", "text": "a"}, keys, chars) == "unsupported_char" and seen == ["char"]


def test_type_bad_text_beats_open_key_mapping():
    obj = {"type": "type", "text": "a\nb", "open": {"key": 225, "mods": 0}}
    assert code_of(obj) == "bad_body"


# move and scroll

@pytest.mark.parametrize("kind, limit", [("move", 1000), ("scroll", 1200)])
class TestPointer:
    def test_limits_are_inclusive(self, kind, limit):
        message = check({"type": kind, "dx": limit, "dy": -limit})
        assert (message.dx, message.dy) == (limit, -limit)

    @pytest.mark.parametrize("delta", [1, -1])
    def test_one_past_the_limit_is_bad_body(self, kind, limit, delta):
        assert code_of({"type": kind, "dx": limit * delta + delta, "dy": 0}) == "bad_body"
        assert code_of({"type": kind, "dx": 0, "dy": limit * delta + delta}) == "bad_body"

    @pytest.mark.parametrize("value", [True, 1.0, 1e2, "1", None, [1]])
    def test_deltas_must_be_integers(self, kind, limit, value):
        assert code_of({"type": kind, "dx": value, "dy": 0}) == "bad_body"
        assert code_of({"type": kind, "dx": 0, "dy": value}) == "bad_body"

    def test_missing_or_extra_fields(self, kind, limit):
        assert code_of({"type": kind, "dx": 1}) == "bad_body"
        assert code_of({"type": kind, "dy": 1}) == "bad_body"
        assert code_of({"type": kind, "dx": 1, "dy": 1, "speed": 2}) == "bad_body"


def test_move_and_scroll_limits_differ():
    assert isinstance(check({"type": "move", "dx": 0, "dy": 0}), m.Move)
    assert check({"type": "scroll", "dx": 1100, "dy": 0}).dx == 1100
    assert code_of({"type": "move", "dx": 1100, "dy": 0}) == "bad_body"


# button

@pytest.mark.parametrize("button", ["left", "right"])
@pytest.mark.parametrize("state, down", [("down", True), ("up", False)])
def test_button_values(button, state, down):
    assert check({"type": "button", "button": button, "state": state}) == m.Button(button, down)


@pytest.mark.parametrize("value", ["middle", "LEFT", "", "down", 1, None, True, ["left"]])
def test_button_name_must_be_left_or_right(value):
    assert code_of({"type": "button", "button": value, "state": "down"}) == "bad_body"


@pytest.mark.parametrize("value", ["press", "DOWN", "", "left", 1, None, False, ["up"]])
def test_button_state_must_be_down_or_up(value):
    assert code_of({"type": "button", "button": "left", "state": value}) == "bad_body"


def test_button_missing_or_extra_fields():
    assert code_of({"type": "button", "button": "left"}) == "bad_body"
    assert code_of({"type": "button", "state": "down"}) == "bad_body"
    assert code_of({"type": "button", "button": "left", "state": "down", "count": 1}) == "bad_body"


# repr never shows payloads

@pytest.mark.parametrize(
    "message",
    [
        m.Press(30, 7),
        m.TypeText("hunter2-password", (40, 3), True),
        m.Move(731, 12),
        m.Button("left", True),
        m.Scroll(733, 9),
    ],
)
def test_repr_hides_payload_fields(message):
    text = repr(message)
    assert text == f"{type(message).__name__}()"


# helpers

def test_parse_hex():
    assert m.parse_hex("0aff", 2) == b"\x0a\xff"
    for bad in ["0AFF", "0af", "0aff00", "0x0a", " 0aff", "0aff\n", "zzzz", "", None, 5, b"0aff", ["0aff"]]:
        assert m.parse_hex(bad, 2) is None


def test_truncate_utf8_never_splits_a_character():
    assert m.truncate_utf8("abc", 63) == "abc"
    assert m.truncate_utf8("a" * 100, 63) == "a" * 63
    assert m.truncate_utf8("é" * 40, 63) == "é" * 31
    assert m.truncate_utf8("😀" * 20, 63) == "😀" * 15
    assert m.truncate_utf8("ab😀", 3) == "ab"
    assert m.truncate_utf8("", 63) == ""
    assert m.truncate_utf8("bad\udc80name", 63) == "bad?name"


# reply bodies

def test_ok_body():
    assert m.ok_body(b"\x01" * 8, 7) == {"type": "ok", "sender": "01" * 8, "counter": 7}


def test_welcome_body_and_hostname_cut():
    body = m.welcome_body(b"\x02" * 8, 3, b"\xaa" * 16, "é" * 40)
    assert body == {
        "type": "welcome",
        "sender": "02" * 8,
        "counter": 3,
        "pluginId": "aa" * 16,
        "maxVersion": 1,
        "hostname": "é" * 31,
    }
    assert m.welcome_body(b"\x02" * 8, 3, b"\xaa" * 16, "deck")["hostname"] == "deck"


def test_error_body_has_retry_only_for_rate_limited():
    assert m.error_body(b"\x03" * 8, 9, "rate_limited", 40) == {
        "type": "error",
        "sender": "03" * 8,
        "counter": 9,
        "error": "rate_limited",
        "retryAfterMs": 40,
    }
    for code in ["bad_body", "replayed", "challenge_required", "unsupported_key", "internal"]:
        assert "retryAfterMs" not in m.error_body(b"\x03" * 8, 9, code)
        with pytest.raises(ValueError):
            m.error_body(b"\x03" * 8, 9, code, 5)


@pytest.mark.parametrize("retry", [None, 0, -1])
def test_error_body_rate_limited_needs_a_retry_of_at_least_one(retry):
    with pytest.raises(ValueError):
        m.error_body(b"\x03" * 8, 9, "rate_limited", retry)


def test_encode_body_is_compact_sorted_and_keeps_utf8():
    assert m.encode_body({"b": 1, "a": "é", "c": [1, {"z": 1, "y": 2}]}) == '{"a":"é","b":1,"c":[1,{"y":2,"z":1}]}'.encode()
