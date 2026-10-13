# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-13

### Added

- ANSI X9.24-1:2009 TDES DUKPT: `derive_ipek`, `derive_key`, and the key
  variants `pin_key`, `mac_request_key`, `mac_response_key`,
  `data_request_key` and `data_response_key`.
- KSN helpers `ksn_counter`, `ksn_with_counter` and `next_ksn` (skips counters
  with more than ten 1 bits; raises `KSNExhaustedError` after 0x1FF800).
- ISO 9564-1 format 0 PIN blocks: `encode_pin_block`, `decode_pin_block`,
  `encrypt_pin`, `decrypt_pin`.
- `pydukpt.compat`: the `dukpt` 1.0.1 API (`DUKPT`, `Server`, `Client`,
  `InvalidDUKPTArguments`) with ANSI-correct keys for every counter.
- Tests against the published ANSI X9.24-1 Annex A.4.2 vectors and 477
  vectors generated with moov-io/dukpt and cross-checked with
  varhenn/dukpt_des_pinblock.

[Unreleased]: https://github.com/mahmoudimus/pydukpt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mahmoudimus/pydukpt/releases/tag/v0.1.0
