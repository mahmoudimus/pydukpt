"""pydukpt.compat against dukpt 1.0.1's API and recorded 1.0.1 outputs."""

from __future__ import annotations

from typing import Any

import pytest

import pydukpt
from pydukpt import KSNExhaustedError
from pydukpt.compat import BDK_LEN, DUKPT, KSN_LEN, Client, InvalidDUKPTArguments, Server

from conftest import VECTORS, h

BDK = h("0123456789ABCDEFFEDCBA9876543210")
KSN = h("FFFF9876543210E00000")
IPEK = h("6AC292FAA1315B4D858AB3A3D7D5933A")
UPSTREAM = VECTORS["dukpt_1_0_1"]
EXPECTED = {(c["bdk"], c["ksn"]): c for c in VECTORS["cases"]}


class FakeBitArray:
    """Stands in for bitstring.BitArray, which exposes its value as .bytes."""

    def __init__(self, data: bytes) -> None:
        self.bytes = data


def _ctr(ksn_hex: str) -> int:
    return pydukpt.ksn_counter(h(ksn_hex))


LOW = [u for u in UPSTREAM if _ctr(u["ksn"]) < 0x200 and not h(u["ksn"])[7] & 0x1F]


def test_upstream_fixture_shape() -> None:
    assert len(LOW) >= 50
    assert any(_ctr(u["ksn"]) >= 0x200 for u in UPSTREAM)


@pytest.mark.parametrize("u", LOW, ids=lambda u: u["ksn"])
def test_agrees_with_1_0_1_below_0x200(u: dict[str, Any]) -> None:
    server = Server(h(u["bdk"]))
    assert server.generate_ipek(h(u["ksn"])) == h(u["ipek"])
    assert server.gen_key(h(u["ksn"])) == h(u["key"])


def test_1_0_1_is_wrong_from_0x200() -> None:
    # Every recorded 1.0.1 key for a counter with a bit >= 0x200 set differs
    # from moov-io/dukpt; ours matches moov-io/dukpt.
    high = [u for u in UPSTREAM if _ctr(u["ksn"]) >= 0x200]
    assert high
    for u in high:
        expected = EXPECTED[(u["bdk"], u["ksn"])]
        assert u["key"] != expected["key"]
        assert Server(h(u["bdk"])).gen_key(h(u["ksn"])) == h(expected["key"])
    # 1.0.1 returns the IPEK itself for counters 0x200 and 0x400.
    for c in (0x200, 0x400):
        ksn = pydukpt.ksn_with_counter(KSN, c).hex()
        u = next(u for u in UPSTREAM if u["ksn"] == ksn and u["bdk"] == BDK.hex())
        assert u["key"] == u["ipek"]


def test_1_0_1_right_ipek_uses_counter_bits() -> None:
    # Counter bit 16 or above set: 1.0.1's IPEK differs; ours ignores the counter.
    wrong = [u for u in UPSTREAM if h(u["ksn"])[7] & 0x1F]
    assert wrong
    for u in wrong:
        expected = EXPECTED[(u["bdk"], u["ksn"])]
        assert u["ipek"][:16] == expected["ipek"][:16]
        assert u["ipek"][16:] != expected["ipek"][16:]
        assert Server(h(u["bdk"])).generate_ipek(h(u["ksn"])) == h(expected["ipek"])


def test_live_dukpt_1_0_1_if_installed() -> None:
    dukpt = pytest.importorskip("dukpt")
    bitstring = pytest.importorskip("bitstring")
    for c in [1, 2, 0x55, 0x1FF]:
        ksn = pydukpt.ksn_with_counter(KSN, c)
        theirs = dukpt.Server(BDK)
        ipek = theirs.generate_ipek(bitstring.BitArray(bytes=ksn))
        key = theirs.derive_key(ipek, bitstring.BitArray(bytes=ksn)).bytes
        assert Server(BDK).gen_key(ksn) == key


def test_module_constants() -> None:
    assert BDK_LEN == DUKPT.BDK_LEN == 16
    assert KSN_LEN == DUKPT.KSN_LEN == 10
    assert DUKPT._pin_mask == pydukpt.PIN_VARIANT
    assert DUKPT._mac_req_mask == h("000000000000FF00000000000000FF00")
    assert DUKPT._mac_resp_mask == h("00000000FF00000000000000FF000000")
    assert DUKPT._mac_data_req == h("0000000000FF00000000000000FF0000")
    assert DUKPT._mac_data_resp == h("000000FF00000000000000FF00000000")


def test_server_methods() -> None:
    server = Server(BDK)
    ksn = h("FFFF9876543210E00003")
    assert server.generate_ipek(ksn) == IPEK
    assert server._tdes_key == BDK + BDK[:8]
    server.generate_left_ipek(ksn)
    assert server._ipek == IPEK[:8]
    server.generate_right_ipek(ksn)
    assert server._ipek == IPEK
    assert server.gen_key(ksn) == h("0DF3D9422ACA56E547676D07AD6BADFA")
    assert server._cur_key == h("0DF3D9422ACA56E547676D07AD6BADFA")
    assert server.derive_key(IPEK, ksn) == h("0DF3D9422ACA56E547676D07AD6BADFA")


def test_bitarray_like_arguments() -> None:
    server = Server(FakeBitArray(BDK))
    ksn = FakeBitArray(h("FFFF9876543210E00001"))
    assert server.gen_key(ksn) == h("042666B49184CFA368DE9628D0397BC9")
    assert server.derive_key(FakeBitArray(IPEK), ksn) == h("042666B49184CFA368DE9628D0397BC9")
    client = Client(FakeBitArray(IPEK), FakeBitArray(KSN))
    assert client.gen_key()["key"] == h("042666B49184CFA368DE9628D0397BC9")


def test_random_server() -> None:
    server = Server()
    assert len(server.bdk) == 16
    assert server._bdk == server.bdk
    ksn = server.generate_ksn()
    assert len(ksn) == 10
    assert pydukpt.ksn_counter(ksn) == 0
    assert len(server.generate_bdk()) == 16


def test_counter_helpers() -> None:
    d = DUKPT(bdk=BDK)
    assert d.reset_counter(h("FFFF9876543210FFFFFF")) == KSN
    assert d.reset_counter(h("FFFF")) is None
    assert d.copy_counter(h("FFFF9876543210FFFFFF")) == h("1FFFFF")
    assert d.copy_counter(h("E00005")) == h("000005")
    with pytest.raises(ValueError, match="at least 3 bytes"):
        d.copy_counter(h("FF"))


def test_client_sequence() -> None:
    client = Client(IPEK, KSN)  # advances to counter 1 on construction
    expected = [
        ("FFFF9876543210E00001", "042666B49184CFA368DE9628D0397BC9"),
        ("FFFF9876543210E00002", "C46551CEF9FD24B0AA9AD834130D3BC7"),
        ("FFFF9876543210E00003", "0DF3D9422ACA56E547676D07AD6BADFA"),
        ("FFFF9876543210E00004", "279C0F6AEED0BE652B2C733E1383AE91"),
        ("FFFF9876543210E00005", "5F8DC6D2C845C125508DDC048093B83F"),
    ]
    for ksn, key in expected:
        assert client.gen_key() == {"ksn": h(ksn), "key": h(key)}


def test_client_skips_counters_with_more_than_ten_one_bits() -> None:
    client = Client(IPEK, pydukpt.ksn_with_counter(KSN, 0x7FD))
    assert pydukpt.ksn_counter(client.gen_key()["ksn"]) == 0x7FE
    assert pydukpt.ksn_counter(client.gen_key()["ksn"]) == 0x800  # not 0x7FF


def test_client_exhaustion() -> None:
    last = pydukpt.ksn_with_counter(KSN, 0x1FF7FF)
    client = Client(IPEK, last)
    info = client.gen_key()
    assert pydukpt.ksn_counter(info["ksn"]) == pydukpt.MAX_COUNTER
    assert info["key"] == pydukpt.derive_key(IPEK, info["ksn"])
    with pytest.raises(KSNExhaustedError):
        client.gen_key()
    with pytest.raises(KSNExhaustedError):
        Client(IPEK, pydukpt.ksn_with_counter(KSN, pydukpt.MAX_COUNTER))


def test_client_and_server_agree() -> None:
    server = Server(BDK)
    client = Client(server.generate_ipek(KSN), KSN)
    for _ in range(20):
        info = client.gen_key()
        assert server.gen_key(info["ksn"]) == info["key"]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({}, "Must have either ipek or bdk"),
        ({"bdk": b""}, "Must have either ipek or bdk"),
        ({"bdk": BDK[:15]}, "BDK must have a length of 16"),
        ({"ipek": IPEK[:8], "ksn": KSN}, "IPEK must have a length of 16"),
        ({"ipek": IPEK, "ksn": KSN[:8]}, "KSN must have a length of 10"),
        ({"ipek": IPEK}, "Must have a ksn"),
    ],
)
def test_invalid_arguments(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(InvalidDUKPTArguments, match=match):
        DUKPT(**kwargs)
    assert issubclass(InvalidDUKPTArguments, ValueError)


def test_server_rejects_empty_bdk() -> None:
    with pytest.raises(InvalidDUKPTArguments):
        Server(b"")


def test_type_errors() -> None:
    with pytest.raises(TypeError):
        Server(BDK).gen_key(KSN.hex())
    with pytest.raises(TypeError):
        DUKPT(bdk=BDK.hex())


def test_method_length_errors() -> None:
    with pytest.raises(ValueError, match="ksn must be 10 bytes"):
        Server(BDK).gen_key(KSN[:8])


def test_increase_counter_without_ksn() -> None:
    with pytest.raises(ValueError, match="no KSN"):
        DUKPT(bdk=BDK).increase_counter()
