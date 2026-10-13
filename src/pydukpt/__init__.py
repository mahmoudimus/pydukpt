"""ANSI X9.24-1:2009 TDES DUKPT key derivation and ISO 9564 format 0 PIN blocks.

Functional API::

    from pydukpt import derive_ipek, derive_key, encrypt_pin

    ipek = derive_ipek(bdk, ksn)
    key = derive_key(ipek, ksn)
    block = encrypt_pin(key, "1234", "4012345678909")

:mod:`pydukpt.compat` mirrors the API of the PyPI ``dukpt`` 1.0.1 package.
"""

from ._core import (
    COUNTER_MASK,
    DATA_REQUEST_VARIANT,
    DATA_RESPONSE_VARIANT,
    KEY_LEN,
    KSN_LEN,
    MAC_REQUEST_VARIANT,
    MAC_RESPONSE_VARIANT,
    MAX_COUNTER,
    MAX_COUNTER_ONE_BITS,
    PIN_VARIANT,
    KSNExhaustedError,
    data_request_key,
    data_response_key,
    derive_ipek,
    derive_key,
    ksn_counter,
    ksn_with_counter,
    mac_request_key,
    mac_response_key,
    next_ksn,
    pin_key,
)
from .pinblock import decode_pin_block, decrypt_pin, encode_pin_block, encrypt_pin

__version__ = "0.1.0"

__all__ = [
    "COUNTER_MASK",
    "DATA_REQUEST_VARIANT",
    "DATA_RESPONSE_VARIANT",
    "KEY_LEN",
    "KSN_LEN",
    "MAC_REQUEST_VARIANT",
    "MAC_RESPONSE_VARIANT",
    "MAX_COUNTER",
    "MAX_COUNTER_ONE_BITS",
    "PIN_VARIANT",
    "KSNExhaustedError",
    "__version__",
    "data_request_key",
    "data_response_key",
    "decode_pin_block",
    "decrypt_pin",
    "derive_ipek",
    "derive_key",
    "encode_pin_block",
    "encrypt_pin",
    "ksn_counter",
    "ksn_with_counter",
    "mac_request_key",
    "mac_response_key",
    "next_ksn",
    "pin_key",
]
