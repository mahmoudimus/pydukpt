from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

import pydukpt
from pydukpt import KSNExhaustedError, ksn_counter, ksn_with_counter, next_ksn

from conftest import VECTORS, h

KSN = h("FFFF9876543210E00000")


def naive_next(counter: int) -> int | None:
    c = counter + 1
    while c <= 0x1FFFFF:
        if bin(c).count("1") <= 10:
            return c
        c += 1
    return None


def test_counter_and_replace() -> None:
    assert ksn_counter(h("FFFF9876543210E00001")) == 1
    assert ksn_counter(h("FFFF9876543210FFFFFF")) == 0x1FFFFF
    assert ksn_counter(KSN) == 0
    # Only the low 5 bits of byte 7 belong to the counter.
    assert ksn_with_counter(KSN, 0x1FFFFF) == h("FFFF9876543210FFFFFF")
    assert ksn_with_counter(h("FFFF9876543210FFFFFF"), 0) == KSN
    assert ksn_with_counter(bytearray(KSN), 5) == h("FFFF9876543210E00005")


@pytest.mark.parametrize("case", VECTORS["next_ksn"], ids=lambda c: c["ksn"])
def test_next_ksn_matches_varhenn(case: dict) -> None:
    if case["next"] is None:
        with pytest.raises(KSNExhaustedError):
            next_ksn(h(case["ksn"]))
    else:
        assert next_ksn(h(case["ksn"])) == h(case["next"])


@pytest.mark.parametrize(
    ("ksn", "expected"),
    [
        # varhenn/dukpt_des_pinblock tests @74befccb
        ("ffff9876543210e00000", "ffff9876543210e00001"),
        ("ffff9876543210e3f0f0", "ffff9876543210e3f100"),
        ("ffff9876543210e0ffcf", "ffff9876543210e10000"),
        ("ffff9876543210effc00", "ffff9876543210f00000"),
        ("ffff9876543210e007fe", "ffff9876543210e00800"),  # 0x7FF has 11 one bits
        ("ffff9876543210fff7ff", "ffff9876543210fff800"),
    ],
)
def test_next_ksn_examples(ksn: str, expected: str) -> None:
    assert next_ksn(h(ksn)) == h(expected)


@pytest.mark.parametrize("counter", [pydukpt.MAX_COUNTER, 0x1FF801, 0x1FFC00, 0x1FFFFF])
def test_next_ksn_exhausted(counter: int) -> None:
    with pytest.raises(KSNExhaustedError):
        next_ksn(ksn_with_counter(KSN, counter))
    assert issubclass(KSNExhaustedError, ValueError)


def test_max_counter_is_last_valid() -> None:
    assert bin(pydukpt.MAX_COUNTER).count("1") == 10
    assert naive_next(pydukpt.MAX_COUNTER) is None


def test_next_ksn_keeps_non_counter_bits() -> None:
    ksn = h("0123456789ABCDEFFFFF")  # counter 0x0FFFFF, top 3 bits of byte 7 = 111
    nxt = next_ksn(ksn)
    assert nxt[:7] == ksn[:7]
    assert nxt[7] & 0xE0 == ksn[7] & 0xE0


@pytest.mark.slow
def test_device_lifetime_is_2_pow_20_minus_1_transactions() -> None:
    ksn, count = KSN, 0
    while True:
        try:
            ksn = next_ksn(ksn)
        except KSNExhaustedError:
            break
        count += 1
    assert count == 2**20 - 1
    assert ksn_counter(ksn) == pydukpt.MAX_COUNTER


@given(st.integers(min_value=0, max_value=0x1FFFFF), st.binary(min_size=10, max_size=10))
def test_next_ksn_property(counter: int, base: bytes) -> None:
    ksn = ksn_with_counter(base, counter)
    expected = naive_next(counter)
    if expected is None:
        with pytest.raises(KSNExhaustedError):
            next_ksn(ksn)
    else:
        assert next_ksn(ksn) == ksn_with_counter(base, expected)


@pytest.mark.parametrize("bad", [b"", b"\0" * 9, b"\0" * 11])
def test_ksn_length(bad: bytes) -> None:
    for fn in (ksn_counter, next_ksn):
        with pytest.raises(ValueError, match="ksn must be 10 bytes"):
            fn(bad)


def test_ksn_type() -> None:
    with pytest.raises(TypeError):
        ksn_counter("FFFF9876543210E00000")  # type: ignore[arg-type]


@pytest.mark.parametrize("counter", [-1, 0x200000])
def test_ksn_with_counter_range(counter: int) -> None:
    with pytest.raises(ValueError, match="counter"):
        ksn_with_counter(KSN, counter)


@pytest.mark.parametrize("counter", [True, 1.0, "1"])
def test_ksn_with_counter_type(counter: object) -> None:
    with pytest.raises(TypeError):
        ksn_with_counter(KSN, counter)  # type: ignore[arg-type]
