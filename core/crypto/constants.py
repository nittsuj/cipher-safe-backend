"""Algorithm and mode sets supported by the cipher layer.

Kept out of :mod:`core.crypto.algorithms` so models and serializers can read the
supported values without pulling in the cipher implementations.
"""

from __future__ import annotations

from typing import Final

SUPPORTED_ALGORITHMS: Final = ("AES", "DES", "RC4")
SUPPORTED_MODES: Final = ("CBC", "CFB", "OFB", "CTR")
DEFAULT_MODE: Final = "CBC"

__all__ = [
    "DEFAULT_MODE",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MODES",
]
