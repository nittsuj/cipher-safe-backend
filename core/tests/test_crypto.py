from __future__ import annotations

from django.test import SimpleTestCase

from ..crypto import MODE_FOR, SUPPORTED_ALGORITHMS, SUPPORTED_MODES, IntegrityError, decrypt, encrypt

from .base import PASSWORD


def _decrypt(result, password=PASSWORD, **overrides):
    params = {
        "ciphertext": result.ciphertext,
        "password": password,
        "algorithm": result.algorithm,
        "salt": result.salt,
        "iv": result.iv,
        "mode": result.mode,
        "tag": result.tag,
    }
    params.update(overrides)
    return decrypt(**params)


class CryptoPrimitiveTests(SimpleTestCase):
    """The core algorithms round-trip, and any change is detected."""

    def test_round_trip_every_algorithm_and_mode(self):
        payloads = [b"", b"short", b"A" * 16, bytes(range(256)) * 32]
        for algorithm in SUPPORTED_ALGORITHMS:
            modes = [None] if algorithm == "RC4" else list(SUPPORTED_MODES)
            for mode in modes:
                for data in payloads:
                    result = encrypt(data, PASSWORD, algorithm, mode)
                    self.assertEqual(_decrypt(result).plaintext, data, f"{algorithm}/{mode} failed")

    def test_default_mode_is_the_chosen_one(self):
        for algorithm in SUPPORTED_ALGORITHMS:
            self.assertEqual(encrypt(b"x", PASSWORD, algorithm).mode, MODE_FOR[algorithm])

    def test_wrong_password_is_rejected_for_every_algorithm(self):
        # Without the MAC, CTR/OFB/CFB/RC4 would silently return garbage here.
        for algorithm in SUPPORTED_ALGORITHMS:
            result = encrypt(b"top secret value", PASSWORD, algorithm)
            with self.assertRaises(IntegrityError, msg=algorithm):
                _decrypt(result, password="definitely-wrong")

    def test_tampering_is_detected(self):
        for algorithm in SUPPORTED_ALGORITHMS:
            result = encrypt(b"blood type O+, allergic to penicillin", PASSWORD, algorithm)
            flipped = bytearray(result.ciphertext)
            flipped[0] ^= 0x01
            cases = {
                "ciphertext": bytes(flipped),
                "tag": bytes(32),
                "salt": bytes(16),
            }
            if result.iv is not None:
                cases["iv"] = bytes(len(result.iv))
            for field, value in cases.items():
                with self.assertRaises(IntegrityError, msg=f"{algorithm}: {field}"):
                    _decrypt(result, **{field: value})

    def test_relabelled_mode_is_detected(self):
        result = encrypt(b"same key stream, other label", PASSWORD, "AES", "CTR")
        with self.assertRaises(IntegrityError):
            _decrypt(result, mode="OFB")

    def test_unknown_algorithm_is_rejected(self):
        with self.assertRaises(ValueError):
            encrypt(b"x", PASSWORD, "AES256")
