# X25519, HKDF-SHA256 and ChaCha20-Poly1305 written from RFC 7748, RFC 5869 and RFC 8439 on the standard library.
# ponytail: Python integer arithmetic is not constant time, so X25519 and Poly1305 run in variable time; a C-backed library would close that.
import hashlib
import hmac
import struct


class CryptoError(Exception):
    pass


class AuthenticationError(CryptoError):
    """The AEAD tag did not match."""


class LowOrderPointError(CryptoError):
    """X25519 produced the all-zero output, which a low-order peer key causes."""


_P = 2**255 - 19
_A24 = 121665
_BASE_POINT = b"\x09" + bytes(31)
_ZERO_32 = bytes(32)

_HASH_LEN = 32
_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_BLOCK_LEN = 64
_MASK32 = 0xFFFFFFFF
_MAX_BLOCKS = 2**32 - 1
_SIGMA = struct.unpack("<4I", b"expand 32-byte k")

_POLY_P = (1 << 130) - 5
_POLY_R_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
_MASK128 = (1 << 128) - 1


def x25519(scalar: bytes, u: bytes) -> bytes:
    """Multiply the point with u-coordinate `u` by the clamped `scalar` (RFC 7748 section 5)."""
    if len(scalar) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    if len(u) != 32:
        raise ValueError("X25519 u-coordinate must be 32 bytes")

    k = int.from_bytes(scalar, "little")
    k &= (1 << 255) - 8
    k |= 1 << 254
    x1 = (int.from_bytes(u, "little") & ((1 << 255) - 1)) % _P

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        mask = -swap
        d = mask & (x2 ^ x3)
        x2 ^= d
        x3 ^= d
        d = mask & (z2 ^ z3)
        z2 ^= d
        z3 ^= d
        swap = kt

        a = x2 + z2
        aa = a * a % _P
        b = x2 - z2
        bb = b * b % _P
        e = aa - bb
        c = x3 + z3
        dd = x3 - z3
        da = dd * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * ((da - cb) ** 2 % _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P

    mask = -swap
    x2 ^= mask & (x2 ^ x3)
    z2 ^= mask & (z2 ^ z3)
    # Fermat inverse, so z2 == 0 (a low-order input) yields 0 instead of an error.
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def x25519_public(private: bytes) -> bytes:
    """The public key for `private`: the scalar times the base point 9."""
    return x25519(private, _BASE_POINT)


def x25519_shared(private: bytes, peer_public: bytes) -> bytes:
    """The Diffie-Hellman shared secret, rejecting the all-zero output of a low-order peer key."""
    secret = x25519(private, peer_public)
    if hmac.compare_digest(secret, _ZERO_32):
        raise LowOrderPointError("X25519 output is all zero")
    return secret


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 section 2.2); an empty salt means HashLen zero bytes."""
    return hmac.digest(salt if salt else bytes(_HASH_LEN), ikm, hashlib.sha256)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 section 2.3)."""
    if len(prk) < _HASH_LEN:
        raise ValueError("HKDF pseudorandom key must be at least 32 bytes")
    if not 0 <= length <= 255 * _HASH_LEN:
        raise ValueError("HKDF output length must be between 0 and 8160")
    okm = bytearray()
    block = b""
    for counter in range(1, -(-length // _HASH_LEN) + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), hashlib.sha256)
        okm += block
    return bytes(okm[:length])


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 extract then expand."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def _quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    a = (a + b) & _MASK32
    d ^= a
    d = ((d << 16) & _MASK32) | (d >> 16)
    c = (c + d) & _MASK32
    b ^= c
    b = ((b << 12) & _MASK32) | (b >> 20)
    a = (a + b) & _MASK32
    d ^= a
    d = ((d << 8) & _MASK32) | (d >> 24)
    c = (c + d) & _MASK32
    b ^= c
    b = ((b << 7) & _MASK32) | (b >> 25)
    return a, b, c, d


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """One 64-byte ChaCha20 keystream block (RFC 8439 section 2.3)."""
    init = (*_SIGMA, *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce))
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = init
    for _ in range(10):
        x0, x4, x8, x12 = _quarter_round(x0, x4, x8, x12)
        x1, x5, x9, x13 = _quarter_round(x1, x5, x9, x13)
        x2, x6, x10, x14 = _quarter_round(x2, x6, x10, x14)
        x3, x7, x11, x15 = _quarter_round(x3, x7, x11, x15)
        x0, x5, x10, x15 = _quarter_round(x0, x5, x10, x15)
        x1, x6, x11, x12 = _quarter_round(x1, x6, x11, x12)
        x2, x7, x8, x13 = _quarter_round(x2, x7, x8, x13)
        x3, x4, x9, x14 = _quarter_round(x3, x4, x9, x14)
    final = (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)
    return struct.pack("<16I", *[(w + i) & _MASK32 for w, i in zip(final, init)])


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt `data` by XOR with the keystream that starts at block `counter`."""
    if not data:
        return b""
    blocks = -(-len(data) // _BLOCK_LEN)
    if counter + blocks - 1 > _MAX_BLOCKS:
        raise ValueError("message too long for a 32-bit block counter")
    stream = b"".join(_chacha20_block(key, counter + i, nonce) for i in range(blocks))
    n = len(data)
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream[:n], "little")).to_bytes(n, "little")


def _poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """The Poly1305 one-time authenticator (RFC 8439 section 2.5)."""
    r = int.from_bytes(key[:16], "little") & _POLY_R_MASK
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i : i + 16] + b"\x01", "little")) * r % _POLY_P
    return ((acc + s) & _MASK128).to_bytes(16, "little")


def _tag(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    mac_data = b"".join(
        (
            aad,
            bytes(-len(aad) % 16),
            ciphertext,
            bytes(-len(ciphertext) % 16),
            struct.pack("<QQ", len(aad), len(ciphertext)),
        )
    )
    return _poly1305_mac(poly_key, mac_data)


def _check_key_nonce(key: bytes, nonce: bytes) -> None:
    if len(key) != _KEY_LEN:
        raise ValueError("AEAD key must be 32 bytes")
    if len(nonce) != _NONCE_LEN:
        raise ValueError("AEAD nonce must be 12 bytes")


def aead_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """ChaCha20-Poly1305 encrypt (RFC 8439 section 2.8); returns (ciphertext, tag)."""
    _check_key_nonce(key, nonce)
    ciphertext = _chacha20_xor(key, 1, nonce, plaintext)
    return ciphertext, _tag(key, nonce, aad, ciphertext)


def aead_open(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """ChaCha20-Poly1305 decrypt; checks the tag first and raises AuthenticationError on a mismatch."""
    _check_key_nonce(key, nonce)
    if len(tag) != _TAG_LEN:
        raise ValueError("AEAD tag must be 16 bytes")
    if not hmac.compare_digest(_tag(key, nonce, aad, ciphertext), tag):
        raise AuthenticationError("AEAD tag mismatch")
    return _chacha20_xor(key, 1, nonce, ciphertext)
