"""Published ANSI X9.24-1:2009 test vectors.

Source: the Annex A.4.2 "Initial Sequence" (KSN FFFF9876543210E00001..5) as
transcribed in moov-io/dukpt pkg/des/des_test.go at commit
9cb72e64a3eab8ec2dd1b9824b9f8ebba2b5ad4d
(https://github.com/moov-io/dukpt/blob/9cb72e64a3eab8ec2dd1b9824b9f8ebba2b5ad4d/pkg/des/des_test.go).
The data and MAC values encrypt / MAC the ASCII string "4012345678909D987"
(zero padded): TDES-CBC with zero IV under the data keys, ANSI X9.19 retail
MAC under the MAC keys.
"""

from __future__ import annotations

import pytest

import pydukpt

from conftest import h
from helpers import retail_mac, tdes_cbc_encrypt

BDK = h("0123456789ABCDEFFEDCBA9876543210")
KSN0 = h("FFFF9876543210E00000")
IPEK = h("6AC292FAA1315B4D858AB3A3D7D5933A")
PIN, PAN, DATA = "1234", "4012345678909", b"4012345678909D987"

# ksn, current key, PIN block, data request, data response, MAC request, MAC response
INITIAL_SEQUENCE = [
    (
        "FFFF9876543210E00001",
        "042666B49184CFA368DE9628D0397BC9",
        "1B9C1845EB993A7A",
        "FC0D53B7EA1FDA9EE68AAF2E70D9B9506229BE2AA993F04F",
        "1FCC89AF66222F27B903898BB2BC8589CDBFDE5EC6AFCC25",
        "9CCC78173FC4FB64",
        "20364223C1FF00FA",
    ),
    (
        "FFFF9876543210E00002",
        "C46551CEF9FD24B0AA9AD834130D3BC7",
        "10A01C8D02C69107",
        "A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13",
        "5B692A6B1FDD5E25B0DEFAFDE1672E402F8011360CFF3508",
        "F608A9BCA6FFC311",
        "D1FCA6BEF05D24D2",
    ),
    (
        "FFFF9876543210E00003",
        "0DF3D9422ACA56E547676D07AD6BADFA",
        "18DC07B94797B466",
        "BD751E65F10E75B6C1D5B1D283496A36C2DE21D993C387A7",
        "345992D4163E4926C927BFD8ABD5D76F087A9CE81D5A27B8",
        "20B59A4FEAC937E3",
        "BAD4CC9CC2AE326C",
    ),
    (
        "FFFF9876543210E00004",
        "279C0F6AEED0BE652B2C733E1383AE91",
        "0BC79509D5645DF7",
        "1118F50947441BBDA3C8C70220021A12EC31CC473F7215F4",
        "418C7413576C0D1819E785D3807AF32334231FDEC23414DB",
        "C7BFA6CC44161828",
        "1EB08AEECE6FF0C2",
    ),
    (
        "FFFF9876543210E00005",
        "5F8DC6D2C845C125508DDC048093B83F",
        "5BC0AF22AD87B327",
        "9FD7BD1EC28845ACA93367A9DA9317BD555C6B33AE22D365",
        "7D4C109E49E83355A556AE949EED359F4404E7A2F0167C00",
        "0202B96339022058",
        "5CBE3E81D1D2A0FB",
    ),
]


def test_ipek() -> None:
    assert pydukpt.derive_ipek(BDK, KSN0) == IPEK


@pytest.mark.parametrize("ksn", [row[0] for row in INITIAL_SEQUENCE])
def test_ipek_ignores_counter(ksn: str) -> None:
    assert pydukpt.derive_ipek(BDK, h(ksn)) == IPEK


def test_counter_zero_gives_ipek() -> None:
    assert pydukpt.derive_key(IPEK, KSN0) == IPEK


@pytest.mark.parametrize(
    ("ksn", "key", "pin_block", "data_req", "data_resp", "mac_req", "mac_resp"),
    INITIAL_SEQUENCE,
)
def test_initial_sequence(
    ksn: str, key: str, pin_block: str, data_req: str, data_resp: str, mac_req: str, mac_resp: str
) -> None:
    current = pydukpt.derive_key(pydukpt.derive_ipek(BDK, h(ksn)), h(ksn))
    assert current == h(key)
    assert pydukpt.encrypt_pin(current, PIN, PAN) == h(pin_block)
    assert pydukpt.decrypt_pin(current, h(pin_block), PAN) == PIN
    assert tdes_cbc_encrypt(pydukpt.data_request_key(current), DATA) == h(data_req)
    assert tdes_cbc_encrypt(pydukpt.data_response_key(current), DATA) == h(data_resp)
    assert retail_mac(pydukpt.mac_request_key(current), DATA) == h(mac_req)
    assert retail_mac(pydukpt.mac_response_key(current), DATA) == h(mac_resp)


def test_pin_key_variant_first_key() -> None:
    # The PIN key for counter 1 (also in varhenn/dukpt_des_pinblock's tests).
    current = h("042666B49184CFA368DE9628D0397BC9")
    assert pydukpt.pin_key(current) == h("042666B49184CF5C68DE9628D0397B36")


def test_pin_block_counter_0x100000() -> None:
    # varhenn/dukpt_des_pinblock README / tests @74befccb: KSN FFFF9876543210F00000
    # (counter 0x100000, the next valid counter after ...EFFC00), PIN 1234,
    # PAN 4012345678909 -> 73EC88AD0AC5830E. moov-io/dukpt gives the same block.
    ksn = h("FFFF9876543210F00000")
    assert pydukpt.next_ksn(h("FFFF9876543210EFFC00")) == ksn
    current = pydukpt.derive_key(IPEK, ksn)
    assert pydukpt.encrypt_pin(current, PIN, PAN) == h("73EC88AD0AC5830E")
    assert pydukpt.decrypt_pin(current, h("73EC88AD0AC5830E"), PAN) == PIN
