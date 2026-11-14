from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID, NameOID
from django.test import SimpleTestCase

from ..crypto import (
    build_signing_certificate,
    certificate_der,
    certificate_fingerprint,
    certificate_pem,
    fingerprint,
    generate_rsa_key_pair,
    load_certificate,
)


class SigningCertificateTests(SimpleTestCase):
    """Self-signed X.509 certificates for signing PDFs."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private_key = generate_rsa_key_pair()
        cls.certificate = build_signing_certificate(cls.private_key, "alice")

    def test_certificate_public_key_matches_key_pair(self):
        self.assertEqual(
            fingerprint(self.certificate.public_key()), fingerprint(self.private_key.public_key())
        )

    def test_certificate_fields(self):
        cert = self.certificate
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "alice")
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, "Cipher Safe")
        self.assertEqual(cert.issuer, cert.subject)
        self.assertEqual(cert.version, x509.Version.v3)
        self.assertIsInstance(cert.signature_hash_algorithm, hashes.SHA256)

        validity = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.assertGreater(validity, datetime.timedelta(days=3 * 365))
        self.assertLess(cert.not_valid_before_utc, datetime.datetime.now(datetime.timezone.utc))

        basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        self.assertTrue(basic.critical)
        self.assertFalse(basic.value.ca)
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        self.assertTrue(usage.critical)
        self.assertTrue(usage.value.digital_signature)
        self.assertTrue(usage.value.content_commitment)
        self.assertFalse(usage.value.key_cert_sign)
        extended = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        self.assertIn("1.3.6.1.5.5.7.3.36", [oid.dotted_string for oid in extended.value])

    def test_certificate_verifies_with_its_own_key(self):
        cert = self.certificate
        self.private_key.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm
        )

    def test_pem_and_der_round_trip(self):
        self.assertEqual(load_certificate(certificate_pem(self.certificate)), self.certificate)
        self.assertEqual(x509.load_der_x509_certificate(certificate_der(self.certificate)), self.certificate)

    def test_fingerprint_is_sha256_of_the_der_certificate(self):
        import hashlib

        expected = hashlib.sha256(certificate_der(self.certificate)).hexdigest().upper()
        self.assertEqual(certificate_fingerprint(self.certificate).replace(":", ""), expected)

    def test_each_certificate_gets_its_own_serial(self):
        other = build_signing_certificate(self.private_key, "alice")
        self.assertNotEqual(other.serial_number, self.certificate.serial_number)
