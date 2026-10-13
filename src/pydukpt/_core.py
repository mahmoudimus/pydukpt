"""ANSI X9.24-1:2009 TDES DUKPT key derivation.

Written from the standard (ANSI X9.24-1:2009, Annex A). Section references in
comments are to that document.
"""

from __future__ import annotations

from typing import Union

from Crypto.Cipher import DES

BytesLike = Union[bytes, bytearray, memoryview]

#: Length of a TDES DUKPT key (BDK, IPEK and every derived key), in bytes.
KEY_LEN = 16
#: Length of a Key Serial Number, in bytes.
KSN_LEN = 10
#: Mask of the 21-bit transaction counter in the rightmost bits of the KSN.
COUNTER_MASK = 0x1FFFFF
#: The highest counter a device may use (the largest 21-bit value with at
#: most ten 1 bits). After it, the device must stop.
MAX_COUNTER = 0x1FF800
#: A counter may have at most this many 1 bits.
MAX_COUNTER_ONE_BITS = 10

# A.6 / A.2: the "C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000" key mask used for
# the right half of the IPEK and in the non-reversible key generation process.
_KEY_MASK = bytes.fromhex("C0C0C0C000000000C0C0C0C000000000")

# A.4.1, Table A-1: variants of the current transaction key.
#: XOR mask giving the PIN encryption key.
PIN_VARIANT = bytes.fromhex("00000000000000FF00000000000000FF")
#: XOR mask giving the MAC key for request messages.
MAC_REQUEST_VARIANT = bytes.fromhex("000000000000FF00000000000000FF00")
#: XOR mask giving the MAC key for response messages.
MAC_RESPONSE_VARIANT = bytes.fromhex("00000000FF00000000000000FF000000")
#: XOR mask giving the data encryption key variant for request messages.
DATA_REQUEST_VARIANT = bytes.fromhex("0000000000FF00000000000000FF0000")
#: XOR mask giving the data encryption key variant for response messages.
DATA_RESPONSE_VARIANT = bytes.fromhex("000000FF00000000000000FF00000000")


class KSNExhaustedError(ValueError):
    """Raised when a KSN has no next transaction counter."""


def _as_bytes(name: str, value: object, length: int | None = None) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like; got {type(value).__name__}")
    data = bytes(value)
    if length is not None and len(data) != length:
        raise ValueError(f"{name} must be {length} bytes; got {len(data)}")
    return data


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _des_encrypt(key8: bytes, block: bytes) -> bytes:
    return DES.new(key8, DES.MODE_ECB).encrypt(block)


def _des_decrypt(key8: bytes, block: bytes) -> bytes:
    return DES.new(key8, DES.MODE_ECB).decrypt(block)


def tdes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 8-byte block with two-key TDES (EDE, keying option 2).

    Built from single DES so that keys whose halves are equal (which
    pycryptodome's ``DES3`` refuses) still give the result the standard
    defines.
    """
    k1, k2 = key[:8], key[8:16]
    return _des_encrypt(k1, _des_decrypt(k2, _des_encrypt(k1, block)))


def tdes_decrypt_block(key: bytes, block: bytes) -> bytes:
    """Decrypt one 8-byte block with two-key TDES (EDE, keying option 2)."""
    k1, k2 = key[:8], key[8:16]
    return _des_decrypt(k1, _des_encrypt(k2, _des_decrypt(k1, block)))


def ksn_counter(ksn: BytesLike) -> int:
    """Return the 21-bit transaction counter of a 10-byte KSN."""
    data = _as_bytes("ksn", ksn, KSN_LEN)
    return int.from_bytes(data[7:], "big") & COUNTER_MASK


def ksn_with_counter(ksn: BytesLike, counter: int) -> bytes:
    """Return ``ksn`` with its 21-bit transaction counter replaced by ``counter``."""
    data = _as_bytes("ksn", ksn, KSN_LEN)
    if isinstance(counter, bool) or not isinstance(counter, int):
        raise TypeError(f"counter must be int; got {type(counter).__name__}")
    if not 0 <= counter <= COUNTER_MASK:
        raise ValueError(f"counter must be in 0..0x1FFFFF; got {counter:#x}")
    tail = (int.from_bytes(data[7:], "big") & ~COUNTER_MASK) | counter
    return data[:7] + tail.to_bytes(3, "big")


def next_ksn(ksn: BytesLike) -> bytes:
    """Return the KSN an originating device uses for its next transaction.

    The counter becomes the smallest value greater than the current one that
    has at most ten 1 bits (A.2: counters with more than ten 1 bits are
    skipped). This also moves a counter that already has more than ten 1
    bits to the next valid one.

    Raises:
        KSNExhaustedError: no such counter exists (the counter is at or past
            ``MAX_COUNTER``, 0x1FF800); the device must stop.
    """
    counter = ksn_counter(ksn)
    candidate = counter + 1
    while bin(candidate).count("1") > MAX_COUNTER_ONE_BITS:
        # Every value between candidate and candidate + lowest set bit keeps
        # all of candidate's 1 bits and adds more, so skip straight past them.
        candidate += candidate & -candidate
    if candidate > COUNTER_MASK:
        raise KSNExhaustedError(f"KSN counter exhausted at {counter:#x}")
    return ksn_with_counter(ksn, candidate)


def derive_ipek(bdk: BytesLike, ksn: BytesLike) -> bytes:
    """Derive the Initial PIN Encryption Key (initial key) from a BDK and KSN.

    A.6: the leftmost 64 bits of the KSN, with the counter bits cleared, are
    TDES-encrypted under the BDK (left half) and under the BDK XOR
    ``C0C0C0C000000000C0C0C0C000000000`` (right half). The counter in ``ksn``
    is ignored, so any KSN of the device gives the same IPEK.
    """
    key = _as_bytes("bdk", bdk, KEY_LEN)
    initial_ksn = ksn_with_counter(ksn, 0)[:8]
    left = tdes_encrypt_block(key, initial_ksn)
    right = tdes_encrypt_block(_xor(key, _KEY_MASK), initial_ksn)
    return left + right


def _non_reversible_key(key: bytes, register: bytes) -> bytes:
    """A.2 non-reversible key generation process for a 16-byte key."""

    def half(k: bytes) -> bytes:
        k_left, k_right = k[:8], k[8:]
        return _xor(k_right, _des_encrypt(k_left, _xor(k_right, register)))

    # The right half of the new key comes from the key itself, the left half
    # from the key XOR the C0C0... mask.
    return half(_xor(key, _KEY_MASK)) + half(key)


def derive_key(ipek: BytesLike, ksn: BytesLike) -> bytes:
    """Derive the current transaction key for ``ksn`` from the IPEK.

    This is the host-side derivation (A.3, "Calculation of the current
    key"): for each 1 bit of the 21-bit counter, from the most significant
    bit down, that bit is set in the KSN register and the key is replaced by
    the non-reversible transformation of the key under the register. With
    counter 0 the IPEK itself is returned. Counters with more than ten 1 bits,
    which a device never uses, are derived the same way.
    """
    key = _as_bytes("ipek", ipek, KEY_LEN)
    data = _as_bytes("ksn", ksn, KSN_LEN)
    counter = ksn_counter(data)
    # Rightmost 64 bits of the KSN with the counter cleared.
    register = int.from_bytes(data[2:], "big") & ~COUNTER_MASK
    bit = 1 << 20
    while bit:
        if counter & bit:
            register |= bit
            key = _non_reversible_key(key, register.to_bytes(8, "big"))
        bit >>= 1
    return key


def pin_key(key: BytesLike) -> bytes:
    """Return the PIN encryption key variant of a current transaction key."""
    return _xor(_as_bytes("key", key, KEY_LEN), PIN_VARIANT)


def mac_request_key(key: BytesLike) -> bytes:
    """Return the request MAC key variant of a current transaction key."""
    return _xor(_as_bytes("key", key, KEY_LEN), MAC_REQUEST_VARIANT)


def mac_response_key(key: BytesLike) -> bytes:
    """Return the response MAC key variant of a current transaction key."""
    return _xor(_as_bytes("key", key, KEY_LEN), MAC_RESPONSE_VARIANT)


def _data_key(key: BytesLike, variant: bytes) -> bytes:
    # A.4.1, Figure A-2: the data variant is passed through a one-way
    # function: each half is TDES-encrypted under the variant itself.
    v = _xor(_as_bytes("key", key, KEY_LEN), variant)
    return tdes_encrypt_block(v, v[:8]) + tdes_encrypt_block(v, v[8:])


def data_request_key(key: BytesLike) -> bytes:
    """Return the request data encryption key for a current transaction key.

    The key is ``key XOR DATA_REQUEST_VARIANT`` with each 8-byte half then
    TDES-encrypted under that variant (ANSI X9.24-1:2009 A.4.1, Figure A-2).
    For the bare variant, XOR with :data:`DATA_REQUEST_VARIANT` yourself.
    """
    return _data_key(key, DATA_REQUEST_VARIANT)


def data_response_key(key: BytesLike) -> bytes:
    """Return the response data encryption key for a current transaction key.

    Derived as :func:`data_request_key`, from :data:`DATA_RESPONSE_VARIANT`.
    """
    return _data_key(key, DATA_RESPONSE_VARIANT)
