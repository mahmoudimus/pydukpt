"""Test-only DES helpers for checking the data and MAC key variants."""

from __future__ import annotations

from Crypto.Cipher import DES, DES3


def zero_pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 8)


def tdes_cbc_encrypt(key: bytes, data: bytes) -> bytes:
    """TDES-CBC, zero IV, zero padding (as in the ANSI X9.24-1 A.4 examples)."""
    return DES3.new(key, DES3.MODE_CBC, iv=b"\0" * 8).encrypt(zero_pad(data))


def retail_mac(key: bytes, data: bytes) -> bytes:
    """ANSI X9.19 retail MAC (ISO 9797-1 algorithm 3), zero padding, full 8 bytes."""
    left, right = key[:8], key[8:]
    state = DES.new(left, DES.MODE_CBC, iv=b"\0" * 8).encrypt(zero_pad(data))[-8:]
    state = DES.new(right, DES.MODE_ECB).decrypt(state)
    return DES.new(left, DES.MODE_ECB).encrypt(state)
