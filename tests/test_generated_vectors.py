"""Vectors from moov-io/dukpt, cross-checked with varhenn/dukpt_des_pinblock.

See tests/fixtures/vectors.json ("provenance") and tools/vectors/.
"""

from __future__ import annotations

from typing import Any

import pytest

import pydukpt

from conftest import VECTORS, h
from helpers import retail_mac, tdes_cbc_encrypt

CASES = VECTORS["cases"]


def _id(case: dict[str, Any]) -> str:
    return f"{case['bdk'][:6]}-{case['ksn']}"


def test_fixture_covers_full_counter_range() -> None:
    counters = {pydukpt.ksn_counter(h(c["ksn"])) for c in CASES}
    assert {0, 1, 0x200, 0x7FF, 0x100000, 0x1FF800, 0x1FFFFF} <= counters
    assert any(h(c["bdk"])[:8] == h(c["bdk"])[8:] for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_case(case: dict[str, Any]) -> None:
    bdk, ksn = h(case["bdk"]), h(case["ksn"])
    ipek = pydukpt.derive_ipek(bdk, ksn)
    assert ipek == h(case["ipek"])
    key = pydukpt.derive_key(ipek, ksn)
    assert key == h(case["key"])
    assert pydukpt.encrypt_pin(key, case["pin"], case["pan"]) == h(case["pin_block"])
    assert pydukpt.decrypt_pin(key, h(case["pin_block"]), case["pan"]) == case["pin"]
    data = h(case["data"])
    assert tdes_cbc_encrypt(pydukpt.data_request_key(key), data) == h(case["data_request_enc"])
    assert tdes_cbc_encrypt(pydukpt.data_response_key(key), data) == h(case["data_response_enc"])
    assert retail_mac(pydukpt.mac_request_key(key), data) == h(case["mac_request"])
    assert retail_mac(pydukpt.mac_response_key(key), data) == h(case["mac_response"])
