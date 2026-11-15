# Packs the envelope header and seals or opens one message under a device key.
import struct
from dataclasses import dataclass

from hotbar import constants as c
from hotbar import crypto

_HEADER = struct.Struct(">BB16s8sQ16s")
assert _HEADER.size == c.HEADER_LEN


@dataclass(frozen=True)
class Header:
    version: int
    direction: int
    device_id: bytes
    sender_id: bytes
    counter: int
    salt: bytes

    def __post_init__(self) -> None:
        # struct would silently pad short byte strings, so check sizes here.
        sizes = (len(self.device_id), len(self.sender_id), len(self.salt))
        if (
            sizes != (c.DEVICE_ID_LEN, c.SENDER_ID_LEN, c.SALT_LEN)
            or not 0 <= self.version <= 0xFF
            or not 0 <= self.direction <= 0xFF
            or not 0 <= self.counter < 2**64
        ):
            raise ValueError("invalid header field")

    def pack(self) -> bytes:
        return _HEADER.pack(
            self.version, self.direction, self.device_id, self.sender_id, self.counter, self.salt
        )

    @staticmethod
    def parse(data: bytes) -> "Header":
        """Reads the header from the first 50 bytes without judging version or direction."""
        if len(data) < c.HEADER_LEN:
            raise ValueError("header too short")
        return Header(*_HEADER.unpack(data[: c.HEADER_LEN]))


def message_key(device_key: bytes, salt: bytes) -> tuple[bytes, bytes]:
    okm = crypto.hkdf(device_key, salt, c.LABEL_MSG, c.MSG_OKM_LEN)
    return okm[:32], okm[32:]


def seal(device_key: bytes, header: Header, body: bytes) -> bytes:
    if not 1 <= len(body) <= c.BODY_MAX:
        raise ValueError("body length out of range")
    packed = header.pack()
    key, nonce = message_key(device_key, header.salt)
    ciphertext, tag = crypto.aead_seal(key, nonce, packed, body)
    return packed + ciphertext + tag


def open_envelope(device_key: bytes, wire: bytes) -> tuple[Header, bytes]:
    """Opens a full wire message; the caller has already checked its length."""
    if not c.MIN_ENVELOPE_LEN <= len(wire) <= c.MAX_ENVELOPE_LEN:
        raise ValueError("envelope length out of range")
    header = Header.parse(wire)
    key, nonce = message_key(device_key, header.salt)
    body = crypto.aead_open(
        key, nonce, wire[: c.HEADER_LEN], wire[c.HEADER_LEN : -c.TAG_LEN], wire[-c.TAG_LEN :]
    )
    return header, body
