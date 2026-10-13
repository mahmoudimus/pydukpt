from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pydukpt import decode_pin_block, decrypt_pin, encode_pin_block, encrypt_pin

from conftest import h

PAN = "4012345678909"
KEY = h("042666B49184CFA368DE9628D0397BC9")


def test_clear_block_example() -> None:
    # PIN field 041234FFFFFFFFFF XOR PAN field 0000401234567890.
    assert encode_pin_block("1234", PAN) == h("041274EDCBA9876F")
    assert decode_pin_block(h("041274EDCBA9876F"), PAN) == "1234"


def test_pin_length_is_one_hex_nibble() -> None:
    block = encode_pin_block("123456789012", "0000000000000")
    assert block == h("0C123456789012FF")


def test_short_pan_is_zero_padded() -> None:
    # 8 digits: the 7 digits before the check digit, right-justified.
    assert encode_pin_block("1234", "12345678") == bytes(
        a ^ b for a, b in zip(h("041234FFFFFFFFFF"), h("0000000001234567"))
    )


def test_long_pan_uses_rightmost_12_before_check_digit() -> None:
    assert encode_pin_block("1234", "9994012345678909") == encode_pin_block("1234", PAN)


@given(
    st.text("0123456789", min_size=4, max_size=12),
    st.text("0123456789", min_size=8, max_size=19),
    st.binary(min_size=16, max_size=16),
)
def test_round_trip(pin: str, pan: str, key: bytes) -> None:
    assert decode_pin_block(encode_pin_block(pin, pan), pan) == pin
    assert decrypt_pin(key, encrypt_pin(key, pin, pan), pan) == pin


@pytest.mark.parametrize(
    "pin", ["123", "1234567890123", "12a4", "", "\uff11\uff12\uff13\uff14", " 1234"]
)
def test_bad_pin(pin: str) -> None:
    with pytest.raises(ValueError, match="pin must be 4 to 12 decimal digits"):
        encode_pin_block(pin, PAN)


@pytest.mark.parametrize("pan", ["1234567", "1" * 20, "40123456789O9", ""])
def test_bad_pan(pan: str) -> None:
    with pytest.raises(ValueError, match="pan must be 8 to 19 decimal digits"):
        encode_pin_block("1234", pan)


def test_types() -> None:
    with pytest.raises(TypeError):
        encode_pin_block(1234, PAN)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        encode_pin_block("1234", 4012345678909)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        decode_pin_block("041274EDCBA9876F", PAN)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("clear", "message"),
    [
        ("141234FFFFFFFFFF", "format 0"),  # control nibble 1
        ("031234FFFFFFFFFF", "PIN length"),
        ("0D1234FFFFFFFFFF", "PIN length"),
        ("04123AFFFFFFFFFF", "malformed"),  # non-digit PIN nibble
        ("041234FFFFFFFFFE", "malformed"),  # fill nibble not F
    ],
)
def test_decode_rejects(clear: str, message: str) -> None:
    pan_field = h("0000401234567890")
    block = bytes(a ^ b for a, b in zip(h(clear), pan_field))
    with pytest.raises(ValueError, match=message):
        decode_pin_block(block, PAN)


def test_decrypt_with_wrong_pan_or_key_fails() -> None:
    block = encrypt_pin(KEY, "1234", PAN)
    with pytest.raises(ValueError, match="PIN block"):
        decrypt_pin(KEY, block, "4012345678917")
    with pytest.raises(ValueError, match="PIN block"):
        decrypt_pin(bytes(16), block, PAN)


def test_block_length() -> None:
    with pytest.raises(ValueError, match="8 bytes"):
        decrypt_pin(KEY, b"\0" * 7, PAN)
    with pytest.raises(ValueError, match="8 bytes"):
        decode_pin_block(b"\0" * 9, PAN)
