"""Generate tests/fixtures/vectors.json from independent DUKPT implementations.

usage: python generate.py MOOV_BINARY VARHENN_DIR OUT.json

- Expected values come from moov-io/dukpt (Go, pkg/des), built from
  tools/vectors/moov (see go.mod for the exact module version).
- varhenn/dukpt_des_pinblock (VARHENN_DIR holds dukpt_des_pinblock.py) must
  agree on every IPEK, current key, PIN key and encrypted PIN block it can
  compute, and provides the expected next_ksn results.
- If the PyPI ``dukpt`` 1.0.1 package (and bitstring) is importable, its
  Server.generate_ipek/derive_key outputs are recorded for the
  ``dukpt_1_0_1`` section, to test the compat module against.

pydukpt itself is not imported: the fixture does not depend on the code it
tests. Requires pycryptodome.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import platform
import random
import subprocess
import sys
from pathlib import Path

SEED = 20261013
ANSI_BDK = "0123456789abcdeffedcba9876543210"
ANSI_KSN = "ffff9876543210e00000"
PIN_VARIANT = bytes.fromhex("00000000000000FF00000000000000FF")
MOOV_MODULE = "github.com/moov-io/dukpt v1.0.1-0.20261008193150-9cb72e64a3ea"
MOOV_COMMIT = "9cb72e64a3eab8ec2dd1b9824b9f8ebba2b5ad4d"


def with_counter(ksn_hex: str, counter: int) -> str:
    ksn = bytes.fromhex(ksn_hex)
    tail = (int.from_bytes(ksn[7:], "big") & ~0x1FFFFF) | counter
    return (ksn[:7] + tail.to_bytes(3, "big")).hex()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    moov, varhenn_dir, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    logging.disable(logging.WARNING)  # varhenn warns about counters with > 10 one bits
    sys.path.insert(0, str(varhenn_dir))
    from dukpt_des_pinblock import DukptDesPinBlock  # varhenn

    rng = random.Random(SEED)

    def rand_hex(n: int) -> str:
        return bytes(rng.getrandbits(8) for _ in range(n)).hex()

    half = rand_hex(8)
    bdks = [ANSI_BDK, rand_hex(16), rand_hex(16), half + half]  # last: K1 == K2
    bases = [ANSI_KSN, with_counter(rand_hex(10), 0), with_counter(rand_hex(10), 0)]
    edge = [
        0,
        1,
        2,
        3,
        4,
        5,
        8,
        0x10,
        0x55,
        0xFF,
        0x100,
        0x101,
        0x1FF,
        0x200,
        0x201,
        0x3FF,
        0x400,
        0x7FE,
        0x7FF,
        0x800,
        0x1000,
        0xFFFF,
        0x10000,
        0x10001,
        0xFFFFF,
        0x100000,
        0x1FF800,
        0x1FFE00,
        0x1FFFFF,
    ]
    counters = edge + [rng.getrandbits(21) for _ in range(6)]

    rows = []
    for bdk in bdks:
        for base in bases:
            for c in counters:
                rows.append((bdk, with_counter(base, c)))
    # The ANSI KSN for every counter 1..0x40 (covers the published A.4 sequence).
    rows += [(ANSI_BDK, with_counter(ANSI_KSN, c)) for c in range(6, 0x41)]
    rows = list(dict.fromkeys(rows))

    lines = []
    for bdk, ksn in rows:
        pin = "".join(rng.choice("0123456789") for _ in range(rng.randint(4, 12)))
        pan = "".join(rng.choice("0123456789") for _ in range(rng.randint(13, 19)))
        data = bytes(rng.choice(b"0123456789ABCDEFGHIJ=^ ") for _ in range(rng.randint(1, 48)))
        lines.append(f"{bdk} {ksn} {pin} {pan} {data.hex()}")
    res = subprocess.run(
        [moov], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True
    ).stdout.splitlines()
    assert len(res) == len(lines)
    keys = [
        "bdk",
        "ksn",
        "pin",
        "pan",
        "data",
        "ipek",
        "key",
        "pin_block",
        "data_request_enc",
        "data_response_enc",
        "mac_request",
        "mac_response",
    ]
    cases = [dict(zip(keys, line.split())) for line in res]

    # varhenn cross-check (pycryptodome DES3 refuses keys with K1 == K2).
    checked = checked_pin = 0
    for case in cases:
        bdk = bytes.fromhex(case["bdk"])
        if bdk[:8] == bdk[8:]:
            continue
        v = DukptDesPinBlock(bdk, bytes.fromhex(case["ksn"]), next_ksn_flag=False)
        pin_key = v._generate_pin_key()
        assert v._generate_ipek().hex() == case["ipek"], case
        assert bytes(a ^ b for a, b in zip(pin_key, PIN_VARIANT)).hex() == case["key"], case
        checked += 1
        if len(case["pin"]) > 9:
            # varhenn writes the PIN length as two decimal digits ("11"), not
            # one hex nibble ("B"), so its blocks for 10-12 digit PINs differ.
            continue
        block, _ = v.generate_pinblock(case["pin"], case["pan"])
        assert block.hex() == case["pin_block"], case
        assert v.generate_pin(block, case["pan"]) == case["pin"], case
        checked_pin += 1

    # next_ksn: varhenn is the reference.
    nk_counters = [
        0,
        1,
        0x1FE,
        0x1FF,
        0x3FF,
        0x7FE,
        0x7FF,
        0xFFC00,
        0x1FF7FF,
        0x1FF800,
        0x1FF801,
        0x1FFFFF,
        0x0F0F0,
        0x3F0F0,
        0x0FFCF,
        0xFFC00,
    ]
    nk_counters += [rng.getrandbits(21) for _ in range(40)]
    # Counters with exactly ten 1 bits, which always carry.
    for _ in range(20):
        nk_counters.append(sum(1 << b for b in rng.sample(range(21), 10)))
    next_ksn = []
    for i, c in enumerate(dict.fromkeys(nk_counters)):
        ksn = with_counter(bases[i % len(bases)], c)
        v = DukptDesPinBlock(bytes.fromhex(ANSI_BDK), bytes.fromhex(ksn), next_ksn_flag=False)
        try:
            nxt = bytes(v.next_ksn()).hex()
        except ValueError:
            nxt = None
        next_ksn.append({"ksn": ksn, "next": nxt})

    provenance = {
        "generated": datetime.date.today().isoformat(),
        "generator": "tools/vectors/generate.py",
        "seed": SEED,
        "python": platform.python_version(),
        "expected_values": {
            "implementation": "moov-io/dukpt pkg/des (Go), via tools/vectors/moov",
            "module": MOOV_MODULE,
            "commit": f"https://github.com/moov-io/dukpt/commit/{MOOV_COMMIT}",
            "functions": "DerivationOfInitialKey, DeriveCurrentTransactionKey, "
            "EncryptPin(ISO-0), EncryptData (TDES-CBC, zero IV, zero "
            "padding), GenerateMac (ANSI X9.19 retail MAC, zero padding)",
        },
        "cross_check": {
            "implementation": "https://github.com/varhenn/dukpt_des_pinblock",
            "commit": "74befccbdf8a63e1db7673f871d615626de2ddd5",
            "dukpt_des_pinblock.py_sha256": sha256(varhenn_dir / "dukpt_des_pinblock.py"),
            "agreed": f"IPEK and current key (pin key XOR PIN variant) for {checked} of "
            f"{len(cases)} cases (the rest use a BDK with equal halves, which "
            "pycryptodome DES3 rejects); encrypted PIN block and PIN decryption "
            f"for the {checked_pin} of those with PINs of 4-9 digits (varhenn "
            "encodes the length of 10-12 digit PINs as two decimal digits "
            "instead of one hex nibble)",
            "next_ksn": "expected values are varhenn's DukptDesPinBlock.next_ksn "
            "(null where it raises ValueError: exhausted)",
        },
    }

    doc = {"provenance": provenance, "cases": cases, "next_ksn": next_ksn}

    try:
        import dukpt  # PyPI dukpt 1.0.1
        from bitstring import BitArray
    except ImportError:
        print("dukpt 1.0.1 not importable; dukpt_1_0_1 section omitted", file=sys.stderr)
    else:
        upstream = []
        for case in cases:
            if case["bdk"] not in bdks[:2]:
                continue
            ksn = BitArray(bytes=bytes.fromhex(case["ksn"]))
            server = dukpt.Server(bytes.fromhex(case["bdk"]))
            ipek = server.generate_ipek(ksn).bytes
            key = server.derive_key(BitArray(bytes=ipek), ksn).bytes
            upstream.append(
                {"bdk": case["bdk"], "ksn": case["ksn"], "ipek": ipek.hex(), "key": key.hex()}
            )
        provenance["dukpt_1_0_1"] = {
            "package": "https://pypi.org/project/dukpt/1.0.1/",
            "source": "https://github.com/allen246/dukpt/commit/"
            "d3c66715c2491cb4ab11630d31d20160b4cd6b69",
            "dukpt.py_sha256": sha256(Path(dukpt.__file__)),
            "calls": "Server(bdk).generate_ipek(BitArray(ksn)), "
            "derive_key(BitArray(ipek), BitArray(ksn))",
        }
        doc["dukpt_1_0_1"] = upstream

    out.write_text(json.dumps(doc, indent=1) + "\n")
    print(
        f"{len(cases)} cases ({checked} cross-checked with varhenn), "
        f"{len(next_ksn)} next_ksn, {len(doc.get('dukpt_1_0_1', []))} dukpt 1.0.1",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
