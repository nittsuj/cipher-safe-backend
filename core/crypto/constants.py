"""Algorithm and mode sets supported by the cipher layer.

Kept out of :mod:`core.crypto.algorithms` so models and serializers can read the
supported values without pulling in the cipher implementations.

``MODE_FOR`` is the mode of operation the application actually uses for each
cipher. AES uses GCM, an AEAD mode whose built-in tag replaces the separate
HMAC. DES has a 64-bit block, for which GCM is not defined, so it keeps CTR +
HMAC; RC4 is a stream cipher, has no mode, and also uses HMAC. The other modes
in ``SUPPORTED_MODES`` stay available to the cipher core so the benchmark can
compare them, but stored data is always written with ``MODE_FOR``.
"""

from __future__ import annotations

from typing import Final

SUPPORTED_ALGORITHMS: Final = ("AES", "DES", "RC4")
SUPPORTED_MODES: Final = ("CBC", "CFB", "OFB", "CTR", "GCM")
#: Modes that authenticate on their own (AEAD) and need no HMAC.
AEAD_MODES: Final = ("GCM",)
#: Modes that need a 128-bit block, so DES cannot use them.
BLOCK128_ONLY_MODES: Final = ("GCM",)
DEFAULT_MODE: Final = "CTR"
MODE_FOR: Final = {"AES": "GCM", "DES": "CTR", "RC4": ""}

__all__ = [
    "AEAD_MODES",
    "BLOCK128_ONLY_MODES",
    "DEFAULT_MODE",
    "MODE_FOR",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MODES",
]
