# pydukpt

ANSI X9.24-1:2009 TDES DUKPT (Derived Unique Key Per Transaction) for Python:
initial key (IPEK) and transaction key derivation, the PIN, MAC and data key
variants, KSN counter handling, and ISO 9564-1 format 0 PIN blocks.

It also ships `pydukpt.compat`, a replacement for the API of the PyPI
[`dukpt`](https://pypi.org/project/dukpt/1.0.1/) 1.0.1 package that derives
correct keys for every transaction counter.

- Python 3.9+
- One dependency: [pycryptodome](https://pypi.org/project/pycryptodome/) (DES only)
- Typed (`py.typed`)

```console
pip install pydukpt
```

> **Security.** This library is for host-side processing (the side that
> holds the BDK, normally inside an HSM), for test tooling, and for checking
> other implementations. A Base Derivation Key must never be present on a
> PIN entry device, and in production it should never leave an HSM. Python
> cannot erase keys from memory, and the DES code is not hardened against
> side channels. TDES DUKPT itself is a legacy scheme; new systems should use
> AES DUKPT (ANSI X9.24-3).

## Usage

```python
from pydukpt import derive_ipek, derive_key, encrypt_pin, decrypt_pin, next_ksn

bdk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
ksn = bytes.fromhex("FFFF9876543210E00001")

ipek = derive_ipek(bdk, ksn)  # 6AC292FAA1315B4D858AB3A3D7D5933A
key = derive_key(ipek, ksn)  # 042666B49184CFA368DE9628D0397BC9

block = encrypt_pin(key, "1234", "4012345678909")  # 1B9C1845EB993A7A
assert decrypt_pin(key, block, "4012345678909") == "1234"

next_ksn(ksn)  # FFFF9876543210E00002
```

Data and MAC keys:

```python
from Crypto.Cipher import DES3
from pydukpt import data_request_key, mac_request_key

cipher = DES3.new(data_request_key(key), DES3.MODE_CBC, iv=bytes(8))
mac_key = mac_request_key(key)  # e.g. for an ANSI X9.19 retail MAC
```

Migrating from `dukpt` 1.0.1:

```python
from pydukpt.compat import Server, Client, InvalidDUKPTArguments

server = Server(bdk)
server.gen_key(ksn)  # bytes
client = Client(ipek, ksn)
client.gen_key()  # {"ksn": bytes, "key": bytes}
```

## API

All functions take `bytes`, `bytearray` or `memoryview` and return `bytes`.
A wrong type raises `TypeError`; a wrong length or value raises `ValueError`.
Keys are 16 bytes and KSNs 10 bytes.

### Keys

| Function | Returns |
| --- | --- |
| `derive_ipek(bdk, ksn)` | The initial key (IPEK) for the device. The counter bits of `ksn` are ignored. |
| `derive_key(ipek, ksn)` | The current transaction key for `ksn`. Counter 0 gives the IPEK. |
| `pin_key(key)` | `key` XOR `PIN_VARIANT` |
| `mac_request_key(key)` | `key` XOR `MAC_REQUEST_VARIANT` |
| `mac_response_key(key)` | `key` XOR `MAC_RESPONSE_VARIANT` |
| `data_request_key(key)` | The request data encryption key (see below) |
| `data_response_key(key)` | The response data encryption key (see below) |

`key` is always the current transaction key returned by `derive_key`.

The variant masks are exported as `PIN_VARIANT`, `MAC_REQUEST_VARIANT`,
`MAC_RESPONSE_VARIANT`, `DATA_REQUEST_VARIANT` and `DATA_RESPONSE_VARIANT`
(ANSI X9.24-1:2009 A.4.1, Table A-1).

**Data keys.** `data_request_key` and `data_response_key` XOR the transaction
key with the data variant and then pass the result through a one-way
function: each 8-byte half is TDES-encrypted (ECB) under the variant key
itself (ANSI X9.24-1:2009 A.4.1, Figure A-2). This is what the published
A.4.2 test data, moov-io/dukpt and most HSMs use. Some implementations use the
bare variant instead; to get it, XOR the transaction key with
`DATA_REQUEST_VARIANT` or `DATA_RESPONSE_VARIANT`. The tests check both data
keys against the published encrypted data.

### KSN

The KSN is 80 bits; its rightmost 21 bits are the transaction counter.

| Function / constant | |
| --- | --- |
| `ksn_counter(ksn)` | The 21-bit counter. |
| `ksn_with_counter(ksn, counter)` | `ksn` with its counter replaced. |
| `next_ksn(ksn)` | The KSN with the next counter a device may use: the smallest larger counter with at most ten 1 bits. Raises `KSNExhaustedError` (a `ValueError`) when there is none. |
| `MAX_COUNTER` | `0x1FF800`, the last valid counter. A device can perform 2^20 - 1 transactions (counters 1 to 0x1FF800 with at most ten 1 bits). |
| `COUNTER_MASK`, `KEY_LEN`, `KSN_LEN`, `MAX_COUNTER_ONE_BITS` | `0x1FFFFF`, 16, 10, 10 |

`derive_key` accepts any counter, including ones with more than ten 1 bits,
which a conforming device never sends; it derives them by the same
algorithm.

### PIN blocks (ISO 9564-1 format 0)

| Function | |
| --- | --- |
| `encode_pin_block(pin, pan)` | The clear 8-byte format 0 block. |
| `decode_pin_block(block, pan)` | The PIN. Raises `ValueError` unless the block is a well-formed format 0 block for `pan`. |
| `encrypt_pin(key, pin, pan)` | The block TDES-ECB-encrypted under `pin_key(key)`. |
| `decrypt_pin(key, encrypted_block, pan)` | The PIN. Raises `ValueError` if the result is not a valid block (wrong key, KSN, PAN or format). |

`pin` is 4 to 12 ASCII digits and `pan` the full PAN including its check
digit, 8 to 19 digits. The PAN field is the 12 rightmost digits before the
check digit; a shorter PAN is padded on the left with zeros. The PIN length
is one hex nibble (`4` to `C`).

### `pydukpt.compat`

`DUKPT`, `Server`, `Client`, `InvalidDUKPTArguments`, `BDK_LEN` and `KSN_LEN`,
with the methods of `dukpt` 1.0.1: `derive_key`, `reset_counter`,
`copy_counter`, `increase_counter`, `Server.generate_ksn`,
`Server.generate_bdk`, `Server.generate_ipek`, `Server.generate_left_ipek`,
`Server.generate_right_ipek`, `Server.gen_key` and `Client.gen_key`.

## Differences from `dukpt` 1.0.1

`dukpt` 1.0.1 (source: [allen246/dukpt](https://github.com/allen246/dukpt) at
`d3c66715`, derived from chokepoint/DUKPT) gives wrong keys outside a small
range and partly fails on Python 3. `pydukpt.compat` keeps its names and
fixes the following. The test suite records 1.0.1's actual output for 267
(BDK, KSN) pairs and checks each point.

| | `dukpt` 1.0.1 | `pydukpt.compat` |
| --- | --- | --- |
| Counter bits used by `derive_key` | 9 (shift register starts at `0x000100`) | all 21 |
| Keys for counters >= 0x200 | wrong (for 0x200 and 0x400 it returns the IPEK) | correct |
| Keys for counters < 0x200 | correct | same as 1.0.1 (checked for 135 pairs) |
| Right half of the IPEK | encrypts the KSN with its counter bits, wrong once counter bit 16 or above is set | counter cleared, as for the left half |
| `increase_counter` | on Python 3, `AttributeError` (`generator.next()`); on Python 2, adds 1 to the counter read as a *signed* 21-bit int, so it raises at 0x0FFFFF and wraps 0x1FFFFF to 0 | moves to the next counter with at most ten 1 bits; raises `KSNExhaustedError` after 0x1FF800 |
| `Client.gen_key` at the end | n/a (see above) | returns the key for 0x1FF800, then raises `KSNExhaustedError` |
| `Client(ipek, ksn)` on Python 3 | raises (`generator.next()`) | works |
| Raw `bytes` arguments | `AttributeError` in `generate_ipek`, `derive_key`, `gen_key` | accepted, as are `bytearray`, `memoryview` and objects with a `.bytes` attribute (e.g. `bitstring.BitArray`) |
| Return types | `BitArray` from `derive_key`, `generate_ipek`, `reset_counter`, `copy_counter`, `generate_ksn` | `bytes` everywhere |
| `_pin_mask`, `_mac_*` attributes | `BitArray` | `bytes` |
| Length checks | BDK only | BDK/IPEK 16 bytes, KSN 10 bytes; `InvalidDUKPTArguments` from constructors, `ValueError` from methods |
| `InvalidDUKPTArguments` base class | `Exception` | `ValueError` |
| `Server(b"")` | random BDK (any false value) | `InvalidDUKPTArguments`; only `Server()` / `Server(None)` generate a random BDK |
| Dependencies | pycryptodome, bitstring | pycryptodome |

`Client` advances the counter once on construction, as 1.0.1 does, so the
first `gen_key()` returns the key for the counter after the one passed in.

## Test vectors

`pytest` runs:

- **Published ANSI X9.24-1:2009 vectors**: BDK
  `0123456789ABCDEFFEDCBA9876543210`, KSN `FFFF9876543210E00000`, IPEK
  `6AC292FAA1315B4D858AB3A3D7D5933A`, and the Annex A.4.2 "Initial Sequence"
  for counters 1 to 5: current keys, PIN blocks for PIN 1234 / PAN
  4012345678909 (counter 1: `1B9C1845EB993A7A`), request/response data
  encryption and request/response MACs of `4012345678909D987`. Transcribed
  from moov-io/dukpt `pkg/des/des_test.go` at
  [`9cb72e64`](https://github.com/moov-io/dukpt/blob/9cb72e64a3eab8ec2dd1b9824b9f8ebba2b5ad4d/pkg/des/des_test.go)
  (the standard itself is not freely available). Also the PIN block
  `73EC88AD0AC5830E` for KSN `FFFF9876543210F00000` from
  [varhenn/dukpt_des_pinblock](https://github.com/varhenn/dukpt_des_pinblock).
- **Generated vectors** (`tests/fixtures/vectors.json`, 477 cases, provenance
  in the file): 4 BDKs (including one with equal halves) x 3 KSNs x 35
  counters spanning 0 to 0x1FFFFF, plus the ANSI KSN for counters 1 to 0x40.
  Expected IPEKs, keys, PIN blocks, data encryption and MACs come from
  moov-io/dukpt (Go) at `9cb72e64`; varhenn/dukpt_des_pinblock at
  `74befccb` agrees on every IPEK and key it can compute and on every PIN
  block for PINs of up to 9 digits. Also 75 `next_ksn` cases from varhenn,
  and the outputs of `dukpt` 1.0.1 for 267 of the cases.
- `next_ksn` against a brute-force search (Hypothesis), and a walk through all
  2^20 - 1 counters of a device.
- Error cases and round-trip properties.

To regenerate the fixture (Go 1.26+, a checkout of varhenn/dukpt_des_pinblock,
and optionally `dukpt==1.0.1` and `bitstring` installed):

```console
cd tools/vectors/moov && go build -o moovvectors . && cd -
python tools/vectors/generate.py tools/vectors/moov/moovvectors ../dukpt_des_pinblock tests/fixtures/vectors.json
```

The output is deterministic (fixed seed) apart from the `generated` date.

## Decisions and assumptions

- **Scope.** TDES DUKPT per ANSI X9.24-1:2009 with double-length (16-byte)
  keys. AES DUKPT (ANSI X9.24-3-2017) is not implemented.
- **KSN length.** KSNs must be 10 bytes. Some libraries accept an 8-byte KSN
  and left-pad it with `FF`; pydukpt does not guess.
- **TDES.** Two-key TDES (EDE) is built from single DES, so a BDK or key with
  equal halves (which pycryptodome's `DES3` refuses) still gives the value the
  algorithm defines. moov-io/dukpt agrees on such a BDK in the fixture.
- **Counter 0 and counters with more than ten 1 bits** are derived like any
  other counter (counter 0 gives the IPEK); only `next_ksn` enforces the
  ten-bit rule.
- **PAN length.** 8 to 19 digits (ISO/IEC 7812-1), left-padded with zeros
  when there are fewer than 12 digits before the check digit. moov-io/dukpt
  requires at least 13 digits; the generated vectors use 13 to 19.
- **Data keys** use the one-way function step described above.
- Section numbers (A.2, A.4.1, A.6, ...) follow the citations in moov-io/dukpt;
  they were not checked against the text of the standard.

## Standards

- ANSI X9.24-1:2009, *Retail Financial Services Symmetric Key Management,
  Part 1: Using Symmetric Techniques* (Annex A: DUKPT).
- ISO 9564-1, *Financial services - Personal Identification Number (PIN)
  management and security, Part 1* (PIN block format 0).
- ANSI X9.19 / ISO 9797-1 MAC algorithm 3 (retail MAC; used only by the
  tests).

## Roadmap

- AES DUKPT (ANSI X9.24-3-2017).
- ISO 9564 format 1, 3 and 4 PIN blocks.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
