from __future__ import annotations

from io import BytesIO
from pathlib import Path

from asn1crypto import x509 as asn1_x509
from django.db import IntegrityError as DatabaseIntegrityError
from django.db.models import ProtectedError
from django.test import SimpleTestCase
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from ..constants import KEY_PURPOSE_SIGNING
from ..crypto import build_signing_certificate, certificate_der, generate_rsa_key_pair
from ..models import PdfSignature, User
from ..services import ensure_key_pair
from ..signing import SIGNATURE_FIELD, AlreadySigned, EncryptedPdf, NotAPdf, is_pdf, sign_pdf
from .base import PASSWORD, AuthenticatedApiTestCase

SAMPLE = (Path(__file__).parent / "fixtures" / "sample.pdf").read_bytes()


class SignPdfTests(SimpleTestCase):
    """Signing PDF bytes with our own key and self-signed certificate."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = generate_rsa_key_pair()
        cls.certificate = build_signing_certificate(cls.key, "alice")
        cls.signed, cls.sign_ms = sign_pdf(SAMPLE, cls.key, cls.certificate, "alice")

    def _signatures(self, data):
        return PdfFileReader(BytesIO(data)).embedded_signatures

    def test_signed_pdf_has_one_embedded_signature(self):
        [signature] = self._signatures(self.signed)
        self.assertEqual(signature.field_name, SIGNATURE_FIELD)
        self.assertGreater(self.sign_ms, 0)

    def test_original_bytes_are_a_prefix_of_signed_bytes(self):
        self.assertTrue(self.signed.startswith(SAMPLE))
        self.assertGreater(len(self.signed), len(SAMPLE))

    def test_signature_is_intact_and_valid_for_our_certificate(self):
        [signature] = self._signatures(self.signed)
        trusted = asn1_x509.Certificate.load(certificate_der(self.certificate))
        status = validate_pdf_signature(signature, ValidationContext(trust_roots=[trusted]))
        self.assertTrue(status.intact)
        self.assertTrue(status.valid)
        self.assertTrue(status.bottom_line)
        self.assertEqual(status.md_algorithm, "sha256")
        self.assertEqual(status.signing_cert.subject.native["common_name"], "alice")

    def test_signature_covers_the_whole_file_except_itself(self):
        [signature] = self._signatures(self.signed)
        start1, len1, start2, len2 = signature.byte_range
        self.assertEqual(start1, 0)
        self.assertEqual(start2 + len2, len(self.signed))

    def test_changing_a_signed_byte_breaks_the_signature(self):
        tampered = bytearray(self.signed)
        position = self.signed.index(b"HbA1c 7.1")
        tampered[position + 6] = ord("9")  # 7.1 -> 9.1
        [signature] = self._signatures(bytes(tampered))
        trusted = asn1_x509.Certificate.load(certificate_der(self.certificate))
        status = validate_pdf_signature(signature, ValidationContext(trust_roots=[trusted]))
        self.assertFalse(status.intact)

    def test_signing_twice_is_refused(self):
        with self.assertRaises(AlreadySigned):
            sign_pdf(self.signed, self.key, self.certificate, "alice")

    def test_non_pdf_is_refused(self):
        self.assertFalse(is_pdf(b"hello"))
        for data in (b"hello world", b"%PDF-1.7\nnot really a pdf"):
            with self.subTest(data=data[:12]), self.assertRaises(NotAPdf):
                sign_pdf(data, self.key, self.certificate, "alice")

    def test_password_protected_pdf_is_refused(self):
        from pyhanko.pdf_utils.crypt import StandardSecurityHandler
        from pyhanko.pdf_utils.writer import copy_into_new_writer

        writer = copy_into_new_writer(PdfFileReader(BytesIO(SAMPLE)))
        writer.security_handler = StandardSecurityHandler.build_from_pw("secret")
        writer._encrypt = writer.add_object(writer.security_handler.as_pdf_object())
        buffer = BytesIO()
        writer.write(buffer)
        with self.assertRaises(EncryptedPdf):
            sign_pdf(buffer.getvalue(), self.key, self.certificate, "alice")


class PdfSignatureRecordTests(AuthenticatedApiTestCase):
    """The ``PdfSignature`` row and the ``signed`` / ``signed_at`` record fields."""

    def setUp(self):
        super().setUp()
        self.file_id = self._upload()["id"]
        self.alice = User.objects.get(username="alice")
        self.pair, _ = ensure_key_pair(self.alice, KEY_PURPOSE_SIGNING, PASSWORD)

    def _record(self):
        [record] = self.client.get("/api/files/").json()
        return record

    def test_unsigned_record_says_so(self):
        record = self._record()
        self.assertEqual((record["signed"], record["signed_at"]), (False, None))

    def test_signed_record_lists_when_it_was_signed(self):
        PdfSignature.objects.create(
            file_id=self.file_id, key_pair=self.pair, signer_fingerprint=self.pair.fingerprint, sign_ms=12.5
        )
        record = self._record()
        self.assertTrue(record["signed"])
        self.assertIsNotNone(record["signed_at"])
        self.assertEqual(self.client.get(f"/api/files/{self.file_id}/").json()["signed"], True)

    def test_one_signature_per_record(self):
        PdfSignature.objects.create(file_id=self.file_id, key_pair=self.pair, signer_fingerprint="x")
        with self.assertRaises(DatabaseIntegrityError):
            PdfSignature.objects.create(file_id=self.file_id, key_pair=self.pair, signer_fingerprint="x")

    def test_signing_key_is_protected_while_a_signature_uses_it(self):
        PdfSignature.objects.create(file_id=self.file_id, key_pair=self.pair, signer_fingerprint="x")
        with self.assertRaises(ProtectedError):
            self.pair.delete()

    def test_deleting_the_record_deletes_its_signature_row(self):
        PdfSignature.objects.create(file_id=self.file_id, key_pair=self.pair, signer_fingerprint="x")
        self.client.delete(f"/api/files/{self.file_id}/")
        self.assertFalse(PdfSignature.objects.exists())
