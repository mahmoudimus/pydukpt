"""Drop-in replacement for the API of the PyPI ``dukpt`` 1.0.1 package.

``from pydukpt.compat import DUKPT, Server, Client, InvalidDUKPTArguments``
gives the classes, method names and constructor arguments of ``dukpt`` 1.0.1,
but keys are derived as ANSI X9.24-1 specifies for every transaction counter.
This module is new code written against that API; it does not contain code
from ``dukpt``. Differences from 1.0.1:

ANSI X9.24-1 corrections

- ``derive_key`` uses all 21 counter bits. 1.0.1 ignores counter bits 9-20,
  so its keys are wrong for every counter >= 0x200 (for 0x200 and 0x400 it
  returns the IPEK). Keys for counters below 0x200 are the same.
- ``generate_right_ipek`` clears the counter bits of the KSN as
  ``generate_left_ipek`` does. 1.0.1 does not, so its IPEK is wrong whenever
  counter bit 16 or above is set.
- ``increase_counter`` moves to the next counter with at most ten 1 bits (as
  :func:`pydukpt.next_ksn` does) and raises :class:`pydukpt.KSNExhaustedError`
  after 0x1FF800. 1.0.1 raises ``AttributeError`` on Python 3; on Python 2
  it adds one to the counter read as a *signed* 21-bit integer, which raises
  at 0x0FFFFF and wraps 0x1FFFFF to 0.
  ``Client.gen_key`` returns the key for the last counter and raises on the
  call after it.

Python 3 and type differences

- Every method that 1.0.1 documents as returning a ``bitstring.BitArray``
  returns ``bytes``. Arguments may be ``bytes``, ``bytearray``,
  ``memoryview`` or any object with a ``bytes`` attribute holding bytes (such
  as a ``BitArray``); anything else raises ``TypeError``. 1.0.1 fails on
  Python 3 when given raw bytes in several places, and ``Client`` cannot be
  constructed there at all.
- ``bitstring`` is not a dependency. The ``_pin_mask`` and ``_mac_*``
  attributes are ``bytes``.
- Lengths are checked: a BDK or IPEK must be 16 bytes and a KSN 10 bytes.
  Wrong lengths passed to a constructor raise :class:`InvalidDUKPTArguments`;
  passed to a method, ``ValueError``. ``InvalidDUKPTArguments`` subclasses
  ``ValueError`` (in 1.0.1 it subclasses ``Exception``).
- ``Server(bdk)`` uses ``bdk`` unless it is ``None``. 1.0.1 generates a random
  BDK for any false value, including ``b""``.
"""

from __future__ import annotations

from typing import Any

from Crypto.Random import get_random_bytes

from . import _core
from ._core import KSNExhaustedError

__all__ = ["BDK_LEN", "DUKPT", "KSN_LEN", "Client", "InvalidDUKPTArguments", "Server"]

BDK_LEN = _core.KEY_LEN
KSN_LEN = _core.KSN_LEN


class InvalidDUKPTArguments(ValueError):
    """Missing or malformed constructor arguments."""


def _raw(name: str, value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    inner = getattr(value, "bytes", None)
    if isinstance(inner, (bytes, bytearray)):
        return bytes(inner)
    raise TypeError(f"{name} must be bytes-like; got {type(value).__name__}")


def _checked(name: str, value: Any, length: int) -> bytes:
    data = _raw(name, value)
    if len(data) != length:
        raise InvalidDUKPTArguments(f"{name.upper()} must have a length of {length}")
    return data


class DUKPT:
    """Base DUKPT class with common functions of both client and server."""

    _pin_mask = _core.PIN_VARIANT
    _mac_req_mask = _core.MAC_REQUEST_VARIANT
    _mac_resp_mask = _core.MAC_RESPONSE_VARIANT
    _mac_data_req = _core.DATA_REQUEST_VARIANT
    _mac_data_resp = _core.DATA_RESPONSE_VARIANT
    _ipek: bytes | None = None
    _tdes_key: bytes | None = None
    _cur_key: bytes | None = None
    _ksn: bytes | None = None
    _bdk: bytes | None = None
    BDK_LEN = BDK_LEN
    KSN_LEN = KSN_LEN

    def __init__(self, bdk: Any = None, ksn: Any = None, ipek: Any = None) -> None:
        """Initialize from either an IPEK and KSN (client) or a BDK (server).

        Args:
            bdk: Base Derivation Key, 16 bytes.
            ksn: Key Serial Number, 10 bytes (used with ``ipek``).
            ipek: Initial PIN Encryption Key, 16 bytes.
        """
        if ipek:
            self._ipek = _checked("ipek", ipek, _core.KEY_LEN)
            if ksn is None:
                raise InvalidDUKPTArguments("Must have a ksn with an ipek")
            self._ksn = _checked("ksn", ksn, KSN_LEN)
        else:
            if not bdk:
                raise InvalidDUKPTArguments("Must have either ipek or bdk")
            self._bdk = _raw("bdk", bdk)
            if len(self._bdk) != self.BDK_LEN:
                raise InvalidDUKPTArguments(f"BDK must have a length of {self.BDK_LEN}")

    def derive_key(self, ipek: Any, ksn: Any) -> bytes:
        """Derive the current transaction key for ``ksn`` from ``ipek``.

        Also stored as ``self._cur_key``.
        """
        self._cur_key = _core.derive_key(_raw("ipek", ipek), _raw("ksn", ksn))
        return self._cur_key

    def reset_counter(self, data: Any) -> bytes | None:
        """Return ``data`` with its last 21 bits (the counter) cleared.

        Returns ``None`` if ``data`` is shorter than 3 bytes.
        """
        raw = _raw("data", data)
        if len(raw) < 3:
            return None
        tail = int.from_bytes(raw[-3:], "big") & ~_core.COUNTER_MASK
        return raw[:-3] + tail.to_bytes(3, "big")

    def copy_counter(self, data: Any) -> bytes:
        """Return the counter (last 21 bits of ``data``) as 3 bytes."""
        raw = _raw("data", data)
        if len(raw) < 3:
            raise ValueError("data must be at least 3 bytes")
        return (int.from_bytes(raw[-3:], "big") & _core.COUNTER_MASK).to_bytes(3, "big")

    def increase_counter(self) -> None:
        """Advance the stored KSN to the next counter a device may use.

        Raises:
            pydukpt.KSNExhaustedError: the counter is at or past 0x1FF800.
        """
        if self._ksn is None:
            raise ValueError("no KSN to increase")
        self._ksn = _core.next_ksn(self._ksn)


class Server(DUKPT):
    """Host side: holds the BDK and derives keys for any KSN."""

    bdk: bytes

    def __init__(self, bdk: Any = None) -> None:
        """Initialize with ``bdk``, or a random 16-byte BDK when it is ``None``."""
        if bdk is None:
            self.bdk = self.generate_bdk()
            bdk = self.bdk
        DUKPT.__init__(self, bdk=bdk)

    def generate_ksn(self) -> bytes:
        """Return a random 10-byte KSN with its counter bits cleared."""
        ksn = self.reset_counter(get_random_bytes(self.KSN_LEN))
        assert ksn is not None
        return ksn

    def generate_bdk(self) -> bytes:
        """Return a random 16-byte BDK."""
        return get_random_bytes(self.BDK_LEN)

    def generate_ipek(self, ksn: Any) -> bytes:
        """Derive the IPEK for ``ksn`` (its counter is ignored)."""
        raw = _raw("ksn", ksn)
        assert self._bdk is not None
        self._tdes_key = self._bdk + self._bdk[:8]
        self.generate_left_ipek(raw)
        self.generate_right_ipek(raw)
        assert self._ipek is not None
        return self._ipek

    def generate_left_ipek(self, ksn: Any) -> None:
        """Set ``self._ipek`` to the left 8 bytes of the IPEK for ``ksn``."""
        assert self._bdk is not None
        self._ipek = _core.derive_ipek(self._bdk, _raw("ksn", ksn))[:8]

    def generate_right_ipek(self, ksn: Any) -> None:
        """Append the right 8 bytes of the IPEK for ``ksn`` to ``self._ipek``."""
        assert self._bdk is not None
        assert self._ipek is not None
        self._ipek = self._ipek[:8] + _core.derive_ipek(self._bdk, _raw("ksn", ksn))[8:]

    def gen_key(self, ksn: Any) -> bytes:
        """Return the current transaction key for ``ksn``."""
        raw = _raw("ksn", ksn)
        return self.derive_key(self.generate_ipek(raw), raw)


class Client(DUKPT):
    """Device side: holds an IPEK and walks the KSN counter.

    As in 1.0.1, the counter is advanced once on construction, so the first
    :meth:`gen_key` uses the counter after the one passed in.
    """

    def __init__(self, ipek: Any, ksn: Any) -> None:
        DUKPT.__init__(self, ipek=ipek, ksn=ksn)
        self._exhausted = False
        self.increase_counter()

    def gen_key(self) -> dict[str, bytes]:
        """Return ``{'ksn': ksn, 'key': key}`` for the current KSN and advance it.

        Raises:
            pydukpt.KSNExhaustedError: the previous call used the last counter.
        """
        if self._exhausted:
            raise KSNExhaustedError("KSN counter exhausted")
        assert self._ipek is not None
        assert self._ksn is not None
        info = {"ksn": self._ksn, "key": self.derive_key(self._ipek, self._ksn)}
        try:
            self.increase_counter()
        except KSNExhaustedError:
            self._exhausted = True
        return info
