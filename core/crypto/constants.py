"""Algorithm and mode sets supported by the cipher layer.

Kept out of :mod:`core.crypto.algorithms` so models and serializers can read the
supported values without pulling in the cipher implementations.

``MODE_FOR`` is the mode of operation the application actually uses for each
cipher. Both block ciphers use CTR so that the AES-vs-DES comparison differs
only in the cipher, not the mode; RC4 is a stream cipher and has no mode. The
other modes in ``SUPPORTED_MODES`` stay available to the cipher core so the
benchmark can compare them, but stored data is always written with
``MODE_FOR``.
"""

from __future__ import annotations

from typing import Final

SUPPORTED_ALGORITHMS: Final = ("AES", "DES", "RC4")
SUPPORTED_MODES: Final = ("CBC", "CFB", "OFB", "CTR")
DEFAULT_MODE: Final = "CTR"
MODE_FOR: Final = {"AES": "CTR", "DES": "CTR", "RC4": ""}

__all__ = [
    "DEFAULT_MODE",
    "MODE_FOR",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MODES",
]
