"""ISO 9564-1 format 0 PIN blocks, encrypted under a DUKPT PIN key."""

from __future__ import annotations

from ._core import (
    BytesLike,
    _as_bytes,
    _xor,
    pin_key,
    tdes_decrypt_block,
    tdes_encrypt_block,
)

__all__ = ["decode_pin_block", "decrypt_pin", "encode_pin_block", "encrypt_pin"]

_PAN_MIN, _PAN_MAX = 8, 19


def _check_digits(name: str, value: object, lo: int, hi: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str; got {type(value).__name__}")
    if not (value.isascii() and value.isdigit() and lo <= len(value) <= hi):
        raise ValueError(f"{name} must be {lo} to {hi} decimal digits")
    return value


def _pan_field(pan: str) -> bytes:
    _check_digits("pan", pan, _PAN_MIN, _PAN_MAX)
    # The 12 rightmost PAN digits excluding the check digit, right-justified
    # in 16 nibbles and padded on the left with zeros.
    return bytes.fromhex(pan[:-1][-12:].rjust(16, "0"))


def encode_pin_block(pin: str, pan: str) -> bytes:
    """Return the clear ISO 9564-1 format 0 PIN block for ``pin`` and ``pan``.

    ``pin`` is 4 to 12 digits; ``pan`` is the full primary account number,
    8 to 19 digits including its check digit.
    """
    _check_digits("pin", pin, 4, 12)
    pin_field = bytes.fromhex(f"0{len(pin):X}{pin}".ljust(16, "F"))
    return _xor(pin_field, _pan_field(pan))


def decode_pin_block(pin_block: BytesLike, pan: str) -> str:
    """Return the PIN in a clear ISO 9564-1 format 0 PIN block.

    Raises:
        ValueError: the block is not a format 0 block for ``pan`` (wrong
            control nibble, PIN length outside 4..12, a non-digit PIN nibble,
            or a fill nibble other than F).
    """
    block = _as_bytes("pin_block", pin_block, 8)
    nibbles = _xor(block, _pan_field(pan)).hex().upper()
    if nibbles[0] != "0":
        raise ValueError("not an ISO 9564-1 format 0 PIN block")
    length = int(nibbles[1], 16)
    if not 4 <= length <= 12:
        raise ValueError("invalid PIN length in PIN block")
    pin, fill = nibbles[2 : 2 + length], nibbles[2 + length :]
    if not pin.isdigit() or fill != "F" * len(fill):
        raise ValueError("malformed PIN block")
    return pin


def encrypt_pin(key: BytesLike, pin: str, pan: str) -> bytes:
    """Encrypt ``pin`` as a format 0 PIN block under a DUKPT transaction key.

    ``key`` is the current transaction key (:func:`pydukpt.derive_key`), not
    the PIN key: the PIN variant is applied here. The block is encrypted with
    TDES in ECB mode.
    """
    return tdes_encrypt_block(pin_key(key), encode_pin_block(pin, pan))


def decrypt_pin(key: BytesLike, encrypted_pin_block: BytesLike, pan: str) -> str:
    """Decrypt a format 0 PIN block encrypted under a DUKPT transaction key.

    ``key`` is the current transaction key, as for :func:`encrypt_pin`.

    Raises:
        ValueError: the decrypted block is not a valid format 0 block for
            ``pan`` (wrong key, KSN or PAN, or a different format).
    """
    block = _as_bytes("encrypted_pin_block", encrypted_pin_block, 8)
    return decode_pin_block(tdes_decrypt_block(pin_key(key), block), pan)
