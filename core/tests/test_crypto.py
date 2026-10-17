from __future__ import annotations

from django.test import TestCase

from ..crypto import SUPPORTED_ALGORITHMS, SUPPORTED_MODES, decrypt, encrypt

from .base import PASSWORD


class CryptoPrimitiveTests(TestCase):
    """The core algorithms round-trip and reject wrong input."""

    def test_round_trip_every_algorithm_and_mode(self):
        payloads = [b"", b"short", b"A" * 16, bytes(range(256)) * 32]
        for algorithm in SUPPORTED_ALGORITHMS:
            modes = [""] if algorithm == "RC4" else list(SUPPORTED_MODES)
            for mode in modes:
                for data in payloads:
                    result = encrypt(data, PASSWORD, algorithm, mode or "CBC")
                    plaintext = decrypt(
                        result.ciphertext,
                        PASSWORD,
                        algorithm,
                        result.salt,
                        result.iv,
                        result.mode,
                    ).plaintext
                    self.assertEqual(plaintext, data, f"{algorithm}/{mode} failed")

    def test_des_and_aes_reject_wrong_password(self):
        for algorithm in ("AES", "DES"):
            result = encrypt(b"top secret value", PASSWORD, algorithm, "CBC")
            with self.assertRaises(ValueError):
                decrypt(
                    result.ciphertext,
                    "definitely-wrong",
                    algorithm,
                    result.salt,
                    result.iv,
                    result.mode,
                )

    def test_unknown_algorithm_is_rejected(self):
        with self.assertRaises(ValueError):
            encrypt(b"x", PASSWORD, "AES256", "CBC")
