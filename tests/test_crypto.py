# Tests for hotbar.crypto against the shared vector files, published RFC values and failure cases.
import json
from pathlib import Path

import pytest

from hotbar import constants, crypto
from hotbar.crypto import AuthenticationError, LowOrderPointError

VECTORS = Path(__file__).resolve().parent / "vectors"
P = 2**255 - 19
BASE = b"\x09" + bytes(31)
ZERO_32 = bytes(32)


def hex_(text: str) -> bytes:
    return bytes.fromhex(text)


def load_cases(name: str) -> list[dict]:
    data = json.loads((VECTORS / name).read_text())
    assert data["formatVersion"] == 1
    return data["cases"]


def ids(cases: list[dict]) -> list[str]:
    return [case["name"] for case in cases]


def flip_bit(data: bytes, index: int = 0) -> bytes:
    mutated = bytearray(data)
    mutated[index] ^= 0x01
    return bytes(mutated)


# Shared vector files.


def check_x25519(case: dict) -> None:
    assert crypto.x25519(hex_(case["scalar"]), hex_(case["u"])) == hex_(case["output"])


def check_hkdf(case: dict) -> None:
    ikm, salt, info = hex_(case["ikm"]), hex_(case["salt"]), hex_(case["info"])
    assert crypto.hkdf_extract(salt, ikm) == hex_(case["prk"])
    assert crypto.hkdf_expand(hex_(case["prk"]), info, case["length"]) == hex_(case["okm"])
    assert crypto.hkdf(ikm, salt, info, case["length"]) == hex_(case["okm"])


def check_aead(case: dict) -> None:
    key, nonce, aad = hex_(case["key"]), hex_(case["nonce"]), hex_(case["aad"])
    plaintext, ciphertext, tag = hex_(case["plaintext"]), hex_(case["ciphertext"]), hex_(case["tag"])
    assert crypto.aead_seal(key, nonce, aad, plaintext) == (ciphertext, tag)
    assert crypto.aead_open(key, nonce, aad, ciphertext, tag) == plaintext


PRIMITIVE_CHECKS = {
    "x25519": check_x25519,
    "hkdf-sha256": check_hkdf,
    "chacha20poly1305": check_aead,
}
PRIMITIVE_CASES = load_cases("primitives.json")


@pytest.mark.parametrize("case", PRIMITIVE_CASES, ids=ids(PRIMITIVE_CASES))
def test_primitive_vector(case):
    check = PRIMITIVE_CHECKS.get(case["kind"])
    if check is None:
        pytest.fail(f"unknown primitive vector kind {case['kind']!r}")
    check(case)


MESSAGE_KEY_CASES = load_cases("message-keys.json")


@pytest.mark.parametrize("case", MESSAGE_KEY_CASES, ids=ids(MESSAGE_KEY_CASES))
def test_message_key_vector(case):
    if case["kind"] != "message-key":
        pytest.fail(f"unknown message key vector kind {case['kind']!r}")
    okm = crypto.hkdf(hex_(case["deviceKey"]), hex_(case["salt"]), constants.LABEL_MSG, constants.MSG_OKM_LEN)
    assert okm == hex_(case["okm"])
    assert okm[:32] == hex_(case["key"])
    assert okm[32:] == hex_(case["nonce"])


PAIRING = {case["name"]: case for case in load_cases("pairing.json")}


def test_pairing_alice_bob_keys():
    case = PAIRING["pair-rfc7748-alice-bob"]
    phone_private = hex_(case["inputs"]["phonePrivate"])
    plugin_private = hex_(case["inputs"]["pluginPrivate"])
    phone_public = hex_(case["derived"]["phonePublic"])
    plugin_public = hex_(case["derived"]["pluginPublic"])
    shared = hex_(case["derived"]["sharedSecret"])

    assert crypto.x25519_public(phone_private) == phone_public
    assert crypto.x25519_public(plugin_private) == plugin_public
    assert crypto.x25519_shared(phone_private, plugin_public) == shared
    assert crypto.x25519_shared(plugin_private, phone_public) == shared


def test_pairing_rejects_low_order_point():
    case = PAIRING["pair-reject-low-order-point"]
    own_private = hex_(case["inputs"]["ownPrivate"])
    peer_public = hex_(case["inputs"]["peerPublic"])
    assert hex_(case["derived"]["sharedSecret"]) == ZERO_32

    assert crypto.x25519(own_private, peer_public) == ZERO_32
    with pytest.raises(LowOrderPointError):
        crypto.x25519_shared(own_private, peer_public)


# Published RFC values that are not in the vector files.


def test_rfc7748_iterated_ladder():
    k = u = BASE
    for i in range(1000):
        k, u = crypto.x25519(k, u), k
        if i == 0:
            assert k == hex_("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    assert k == hex_("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")


RFC5869_CASES = {
    "a.2": (
        bytes(range(0x00, 0x50)),
        bytes(range(0x60, 0xB0)),
        bytes(range(0xB0, 0x100)),
        82,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ),
    "a.3": (
        b"\x0b" * 22,
        b"",
        b"",
        42,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    ),
}


@pytest.mark.parametrize("name", RFC5869_CASES)
def test_rfc5869_appendix_a(name):
    ikm, salt, info, length, prk, okm = RFC5869_CASES[name]
    assert crypto.hkdf_extract(salt, ikm) == hex_(prk)
    assert crypto.hkdf(ikm, salt, info, length) == hex_(okm)


RFC8439_KEY = bytes(range(32))


def test_rfc8439_2_3_2_chacha20_block():
    block = crypto._chacha20_block(RFC8439_KEY, 1, hex_("000000090000004a00000000"))
    assert block == hex_(
        "10f1e7e4d13b5915500fdd1fa32071c4 c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2 b5129cd1de164eb9cbd083e8a2503c4e"
    )


def test_rfc8439_2_4_2_chacha20_encryption():
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    ciphertext = crypto._chacha20_xor(RFC8439_KEY, 1, hex_("000000000000004a00000000"), plaintext)
    assert ciphertext == hex_(
        """6e2e359a2568f98041ba0728dd0d6981 e97e7aec1d4360c20a27afccfd9fae0b
        f91b65c5524733ab8f593dabcd62b357 1639d624e65152ab8f530c359f0861d8
        07ca0dbf500d6a6156a38e088a22b65e 52bc514d16ccf806818ce91ab7793736
        5af90bbf74a35be6b40b8eedf2785e42 874d"""
    )


def test_rfc8439_2_5_2_poly1305():
    key = hex_("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    tag = crypto._poly1305_mac(key, b"Cryptographic Forum Research Group")
    assert tag == hex_("a8061dc1305136c6c22b8baf0c0127a9")


def test_rfc8439_appendix_a_5_aead_decryption():
    key = hex_("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
    nonce = hex_("000000000102030405060708")
    aad = hex_("f33388860000000000004e91")
    ciphertext = hex_(
        """64a0861575861af460f062c79be643bd 5e805cfd345cf389f108670ac76c8cb2
        4c6cfc18755d43eea09ee94e382d26b0 bdb7b73c321b0100d4f03b7f355894cf
        332f830e710b97ce98c8a84abd0b9481 14ad176e008d33bd60f982b1ff37c855
        9797a06ef4f0ef61c186324e2b350638 3606907b6a7c02b0f9f6157b53c867e4
        b9166c767b804d46a59b5216cde7a4e9 9040c5a40433225ee282a1b0a06c523e
        af4534d7f83fa1155b0047718cbc546a 0d072b04b3564eea1b422273f548271a
        0bb2316053fa76991955ebd63159434e cebb4e466dae5a1073a6727627097a10
        49e617d91d361094fa68f0ff77987130 305beaba2eda04df997b714d6c6f2c29
        a6ad5cb4022b02709b"""
    )
    tag = hex_("eead9d67890cbb22392336fea1851f38")
    plaintext = (
        "Internet-Drafts are draft documents valid for a maximum of six months and may be updated, "
        "replaced, or obsoleted by other documents at any time. It is inappropriate to use "
        "Internet-Drafts as reference material or to cite them other than as /“work in progress./”"
    ).encode()

    assert crypto.aead_open(key, nonce, aad, ciphertext, tag) == plaintext
    assert crypto.aead_seal(key, nonce, aad, plaintext) == (ciphertext, tag)


# X25519 edge cases.

LOW_ORDER_U = {
    "zero": 0,
    "one": 1,
    "p-1": P - 1,
    "p (zero, not reduced)": P,
    "p+1 (one, not reduced)": P + 1,
}
OWN_PRIVATE = bytes(range(1, 33))


@pytest.mark.parametrize("u", LOW_ORDER_U.values(), ids=LOW_ORDER_U.keys())
def test_low_order_u_gives_zero_and_is_rejected(u):
    peer = u.to_bytes(32, "little")
    assert crypto.x25519(OWN_PRIVATE, peer) == ZERO_32
    with pytest.raises(LowOrderPointError):
        crypto.x25519_shared(OWN_PRIVATE, peer)


def test_x25519_ignores_top_bit_of_u():
    case = PRIMITIVE_CASES[0]
    u = hex_(case["u"])
    with_top_bit = u[:31] + bytes([u[31] | 0x80])
    assert crypto.x25519(hex_(case["scalar"]), with_top_bit) == hex_(case["output"])


def test_x25519_clamps_scalar():
    case = PRIMITIVE_CASES[0]
    scalar = hex_(case["scalar"])
    unclamped = bytes([scalar[0] | 0x07]) + scalar[1:31] + bytes([scalar[31] & 0x3F | 0x80])
    assert crypto.x25519(unclamped,hex_(case["u"])) == hex_(case["output"])


# AEAD failures.

AEAD_CASE = next(case for case in PRIMITIVE_CASES if case["kind"] == "chacha20poly1305")


def aead_parts() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    return (
        hex_(AEAD_CASE["key"]),
        hex_(AEAD_CASE["nonce"]),
        hex_(AEAD_CASE["aad"]),
        hex_(AEAD_CASE["ciphertext"]),
        hex_(AEAD_CASE["tag"]),
    )


def test_aead_rejects_flipped_tag_bit():
    key, nonce, aad, ciphertext, tag = aead_parts()
    for index in (0, len(tag) - 1):
        with pytest.raises(AuthenticationError):
            crypto.aead_open(key, nonce, aad, ciphertext, flip_bit(tag, index))


def test_aead_rejects_flipped_ciphertext_bit():
    key, nonce, aad, ciphertext, tag = aead_parts()
    for index in (0, len(ciphertext) - 1):
        with pytest.raises(AuthenticationError):
            crypto.aead_open(key, nonce, aad, flip_bit(ciphertext, index), tag)


def test_aead_rejects_flipped_aad_bit():
    key, nonce, aad, ciphertext, tag = aead_parts()
    with pytest.raises(AuthenticationError):
        crypto.aead_open(key, nonce, flip_bit(aad), ciphertext, tag)


def test_aead_rejects_wrong_key_and_nonce():
    key, nonce, aad, ciphertext, tag = aead_parts()
    with pytest.raises(AuthenticationError):
        crypto.aead_open(flip_bit(key), nonce, aad, ciphertext, tag)
    with pytest.raises(AuthenticationError):
        crypto.aead_open(key, flip_bit(nonce), aad, ciphertext, tag)


def test_aead_rejects_truncated_and_extended_ciphertext():
    key, nonce, aad, ciphertext, tag = aead_parts()
    with pytest.raises(AuthenticationError):
        crypto.aead_open(key, nonce, aad, ciphertext[:-1], tag)
    with pytest.raises(AuthenticationError):
        crypto.aead_open(key, nonce, aad, ciphertext + b"\x00", tag)


def test_aead_open_checks_tag_before_decrypting(monkeypatch):
    def decrypt_called(*args, **kwargs):
        raise AssertionError("decrypted before the tag was verified")

    key, nonce, aad, ciphertext, tag = aead_parts()
    monkeypatch.setattr(crypto, "_chacha20_xor", decrypt_called)
    with pytest.raises(AuthenticationError):
        crypto.aead_open(key, nonce, aad, ciphertext, flip_bit(tag))


# Wrong lengths.

KEY = bytes(32)
NONCE = bytes(12)
WRONG_LENGTH_CALLS = {
    "x25519 short scalar": lambda: crypto.x25519(bytes(31), BASE),
    "x25519 long scalar": lambda: crypto.x25519(bytes(33), BASE),
    "x25519 short u": lambda: crypto.x25519(KEY, bytes(31)),
    "x25519 long u": lambda: crypto.x25519(KEY, bytes(33)),
    "x25519_public short": lambda: crypto.x25519_public(bytes(31)),
    "x25519_shared short private": lambda: crypto.x25519_shared(bytes(31), BASE),
    "x25519_shared long peer": lambda: crypto.x25519_shared(KEY, bytes(33)),
    "x25519_shared empty peer": lambda: crypto.x25519_shared(KEY, b""),
    "seal short key": lambda: crypto.aead_seal(bytes(31), NONCE, b"", b"x"),
    "seal long key": lambda: crypto.aead_seal(bytes(33), NONCE, b"", b"x"),
    "seal short nonce": lambda: crypto.aead_seal(KEY, bytes(11), b"", b"x"),
    "seal long nonce": lambda: crypto.aead_seal(KEY, bytes(13), b"", b"x"),
    "open short key": lambda: crypto.aead_open(bytes(31), NONCE, b"", b"", bytes(16)),
    "open short nonce": lambda: crypto.aead_open(KEY, bytes(11), b"", b"", bytes(16)),
    "open long nonce": lambda: crypto.aead_open(KEY, bytes(13), b"", b"", bytes(16)),
    "open short tag": lambda: crypto.aead_open(KEY, NONCE, b"", b"", bytes(15)),
    "open long tag": lambda: crypto.aead_open(KEY, NONCE, b"", b"", bytes(17)),
    "open empty tag": lambda: crypto.aead_open(KEY, NONCE, b"", b"", b""),
    "hkdf_expand short prk": lambda: crypto.hkdf_expand(bytes(31), b"", 16),
    "hkdf_expand negative length": lambda: crypto.hkdf_expand(KEY, b"", -1),
    "hkdf_expand too long": lambda: crypto.hkdf_expand(KEY, b"", 255 * 32 + 1),
}


@pytest.mark.parametrize("call", WRONG_LENGTH_CALLS.values(), ids=WRONG_LENGTH_CALLS.keys())
def test_wrong_length_raises_value_error(call):
    with pytest.raises(ValueError):
        call()


def test_hkdf_expand_length_limits():
    assert crypto.hkdf_expand(KEY, b"", 0) == b""
    assert len(crypto.hkdf_expand(KEY, b"", 255 * 32)) == 255 * 32


# Round trips.

RT_KEY = bytes(range(32))
RT_NONCE = bytes(range(12))


def test_empty_plaintext_and_aad_round_trip():
    ciphertext, tag = crypto.aead_seal(RT_KEY, RT_NONCE, b"", b"")
    assert ciphertext == b""
    assert len(tag) == 16
    assert crypto.aead_open(RT_KEY, RT_NONCE, b"", ciphertext, tag) == b""


def test_max_body_round_trip():
    plaintext = bytes(range(256)) * (constants.BODY_MAX // 256)
    assert len(plaintext) == constants.BODY_MAX
    aad = bytes(range(constants.HEADER_LEN))
    ciphertext, tag = crypto.aead_seal(RT_KEY, RT_NONCE, aad, plaintext)
    assert len(ciphertext) == constants.BODY_MAX
    assert ciphertext != plaintext
    assert crypto.aead_open(RT_KEY, RT_NONCE, aad, ciphertext, tag) == plaintext


@pytest.mark.parametrize("length", [1, 15, 16, 17, 63, 64, 65, 127, 128, 129])
def test_ciphertext_is_keystream_prefix(length):
    keystream, _ = crypto.aead_seal(RT_KEY, RT_NONCE, b"", bytes(200))
    ciphertext, _ = crypto.aead_seal(RT_KEY, RT_NONCE, b"", bytes(length))
    assert ciphertext == keystream[:length]
