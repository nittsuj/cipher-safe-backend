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
            if algorithm == "DES":
                modes.remove("GCM")  # GCM needs a 128-bit block
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

    def test_aes_uses_gcm_with_its_own_tag(self):
        result = encrypt(b"lab result", PASSWORD, "AES")
        self.assertEqual(result.mode, "GCM")
        self.assertEqual(len(result.iv), 12)
        self.assertEqual(len(result.tag), 16)
        self.assertEqual(result.mac_ms, 0.0)

    def test_gcm_tag_tampering_is_detected(self):
        result = encrypt(b"HIV test: negative", PASSWORD, "AES", "GCM")
        tag = bytearray(result.tag)
        tag[0] ^= 0x01
        with self.assertRaises(IntegrityError):
            _decrypt(result, tag=bytes(tag))

    def test_gcm_parameters_are_bound_as_associated_data(self):
        result = encrypt(b"bound to its salt", PASSWORD, "AES", "GCM")
        salt = bytearray(result.salt)
        salt[0] ^= 0x01
        with self.assertRaises(IntegrityError):
            _decrypt(result, salt=bytes(salt))

    def test_des_rejects_gcm(self):
        with self.assertRaises(ValueError):
            encrypt(b"x", PASSWORD, "DES", "GCM")

    def test_legacy_aes_ctr_records_still_decrypt(self):
        # Rows written before the switch to GCM keep their stored mode.
        result = encrypt(b"old record", PASSWORD, "AES", "CTR")
        self.assertEqual(_decrypt(result).plaintext, b"old record")

    def test_unknown_algorithm_is_rejected(self):
        with self.assertRaises(ValueError):
            encrypt(b"x", PASSWORD, "AES256")
