from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import pydukpt

from conftest import h

BDK = h("0123456789ABCDEFFEDCBA9876543210")
KSN = h("FFFF9876543210E00000")
IPEK = h("6AC292FAA1315B4D858AB3A3D7D5933A")


def test_variant_masks() -> None:
    key = bytes(16)
    assert pydukpt.pin_key(key) == pydukpt.PIN_VARIANT
    assert pydukpt.mac_request_key(key) == pydukpt.MAC_REQUEST_VARIANT
    assert pydukpt.mac_response_key(key) == pydukpt.MAC_RESPONSE_VARIANT
    variants = [
        pydukpt.PIN_VARIANT,
        pydukpt.MAC_REQUEST_VARIANT,
        pydukpt.MAC_RESPONSE_VARIANT,
        pydukpt.DATA_REQUEST_VARIANT,
        pydukpt.DATA_RESPONSE_VARIANT,
    ]
    assert len(set(variants)) == 5
    for v in variants:
        assert v[:8] == v[8:]
        assert sum(b != 0 for b in v) == 2


def test_data_keys_are_not_bare_variants() -> None:
    key = h("042666B49184CFA368DE9628D0397BC9")
    bare = bytes(a ^ b for a, b in zip(key, pydukpt.DATA_REQUEST_VARIANT))
    assert pydukpt.data_request_key(key) != bare
    assert pydukpt.data_request_key(key) != pydukpt.data_response_key(key)


def test_accepts_bytes_like() -> None:
    ksn = h("FFFF9876543210E00001")
    expected = pydukpt.derive_key(IPEK, ksn)
    assert pydukpt.derive_key(bytearray(IPEK), memoryview(ksn)) == expected
    assert pydukpt.derive_ipek(bytearray(BDK), bytearray(ksn)) == IPEK
    assert isinstance(pydukpt.derive_key(bytearray(IPEK), ksn), bytes)


@pytest.mark.parametrize(
    ("fn", "args", "exc", "match"),
    [
        (pydukpt.derive_ipek, (BDK[:15], KSN), ValueError, "bdk must be 16 bytes"),
        (pydukpt.derive_ipek, (BDK + b"\0" * 8, KSN), ValueError, "bdk must be 16 bytes"),
        (pydukpt.derive_ipek, (BDK, KSN[:8]), ValueError, "ksn must be 10 bytes"),
        (pydukpt.derive_ipek, (BDK.hex(), KSN), TypeError, "bdk must be bytes-like"),
        (pydukpt.derive_key, (IPEK[:8], KSN), ValueError, "ipek must be 16 bytes"),
        (pydukpt.derive_key, (IPEK, KSN + b"\0"), ValueError, "ksn must be 10 bytes"),
        (pydukpt.derive_key, (IPEK, None), TypeError, "ksn must be bytes-like"),
        (pydukpt.pin_key, (IPEK[:8],), ValueError, "key must be 16 bytes"),
        (pydukpt.data_request_key, ([0] * 16,), TypeError, "key must be bytes-like"),
    ],
)
def test_argument_errors(fn, args, exc, match) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(exc, match=match):
        fn(*args)


def test_equal_halves_bdk() -> None:
    # pycryptodome's DES3 rejects such keys; the derivation is still defined
    # (and matches moov-io/dukpt, see the generated vectors).
    bdk = h("0123456789ABCDEF0123456789ABCDEF")
    assert len(pydukpt.derive_ipek(bdk, KSN)) == 16


@settings(max_examples=50)
@given(st.binary(min_size=16, max_size=16), st.binary(min_size=10, max_size=10))
def test_counter_zero_and_ipek_independent_of_counter(bdk: bytes, ksn: bytes) -> None:
    zero = pydukpt.ksn_with_counter(ksn, 0)
    ipek = pydukpt.derive_ipek(bdk, zero)
    assert pydukpt.derive_ipek(bdk, ksn) == ipek
    assert pydukpt.derive_key(ipek, zero) == ipek


@settings(max_examples=50)
@given(st.binary(min_size=16, max_size=16), st.integers(1, 0x1FFFFF))
def test_derive_key_chain(ipek: bytes, counter: int) -> None:
    # The device-side view: the key for a counter is the one-step derivation
    # from the key of the counter with its lowest 1 bit cleared. The two halves
    # of each step are checked by recomputing that step from the definition.
    ksn = pydukpt.ksn_with_counter(KSN, counter)
    parent = pydukpt.ksn_with_counter(KSN, counter & (counter - 1))
    assert pydukpt.derive_key(ipek, ksn) == _step(pydukpt.derive_key(ipek, parent), ksn)


def _step(key: bytes, ksn: bytes) -> bytes:
    from Crypto.Cipher import DES

    reg = ksn[2:]
    mask = h("C0C0C0C000000000C0C0C0C000000000")

    def half(k: bytes) -> bytes:
        r = bytes(a ^ b for a, b in zip(k[8:], reg))
        e = DES.new(k[:8], DES.MODE_ECB).encrypt(r)
        return bytes(a ^ b for a, b in zip(e, k[8:]))

    return half(bytes(a ^ b for a, b in zip(key, mask))) + half(key)
