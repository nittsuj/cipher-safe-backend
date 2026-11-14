from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from io import BytesIO
from pathlib import Path

from asn1crypto import x509 as asn1_x509
from django.db import IntegrityError as DatabaseIntegrityError
from django.db.models import ProtectedError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from rest_framework import status

from ..constants import KEY_PURPOSE_SIGNING
from ..crypto import (
    build_signing_certificate,
    certificate_der,
    certificate_fingerprint,
    certificate_pem,
    generate_rsa_key_pair,
    load_certificate,
)
from ..models import PdfSignature, StoredFile, User, UserKeyPair
from ..services import ensure_key_pair
from ..signing import SIGNATURE_FIELD, AlreadySigned, EncryptedPdf, NotAPdf, is_pdf, sign_pdf, verify_pdf
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


class PdfUploadHelpers(AuthenticatedApiTestCase):
    """Upload and download helpers for the signing API tests (no tests here)."""

    def _upload_pdf(self, data=SAMPLE, sign=True, content_type="application/pdf", name="lab.pdf"):
        upload = SimpleUploadedFile(name, data, content_type=content_type)
        body = {"file": upload, "category": "DOCUMENT"}
        if sign:
            body["sign"] = "true"
        return self.client.post("/api/files/", body, format="multipart")

    def _download(self, file_id, algorithm):
        response = self.client.get(f"/api/files/{file_id}/download/", {"algorithm": algorithm})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.content


class SignOnUploadTests(PdfUploadHelpers):
    """POST /api/files/ with ``sign=true``."""

    def test_signed_upload_stores_the_signed_pdf_in_every_copy(self):
        response = self._upload_pdf()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.json()["signed"])
        file_id = response.json()["id"]

        copies = {algorithm: self._download(file_id, algorithm) for algorithm in ("AES", "DES", "RC4")}
        self.assertEqual(len(set(copies.values())), 1)  # all three decrypt to the same signed PDF
        signed = copies["AES"]
        self.assertTrue(signed.startswith(SAMPLE))
        [embedded] = PdfFileReader(BytesIO(signed)).embedded_signatures

        pair = UserKeyPair.objects.get(user__username="alice", purpose=KEY_PURPOSE_SIGNING)
        trusted = asn1_x509.Certificate.load(certificate_der(load_certificate(pair.certificate_pem)))
        self.assertTrue(validate_pdf_signature(embedded, ValidationContext(trust_roots=[trusted])).bottom_line)
        self.assertEqual(PdfSignature.objects.get().signer_fingerprint, pair.fingerprint)

    def test_signing_creates_key_pair_on_first_use(self):
        self.assertFalse(UserKeyPair.objects.filter(purpose=KEY_PURPOSE_SIGNING).exists())
        self._upload_pdf()
        self._upload_pdf()
        self.assertEqual(UserKeyPair.objects.filter(purpose=KEY_PURPOSE_SIGNING).count(), 1)

    def test_upload_without_sign_is_unchanged(self):
        response = self._upload_pdf(sign=False)
        self.assertFalse(response.json()["signed"])
        self.assertEqual(self._download(response.json()["id"], "AES"), SAMPLE)
        self.assertFalse(PdfSignature.objects.exists())

    def test_sign_non_pdf_400_and_nothing_stored(self):
        cases = [
            {"data": b"plain text", "content_type": "text/plain", "name": "notes.txt"},
            {"data": b"plain text", "content_type": "application/pdf"},  # says PDF, isn't
            {"data": SAMPLE, "content_type": "text/plain"},  # is a PDF, but not labelled as one
        ]
        for case in cases:
            with self.subTest(case=case["content_type"]):
                response = self._upload_pdf(**case)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertIn("file", response.json())
        self.assertFalse(StoredFile.objects.exists())

    def test_already_signed_pdf_is_409(self):
        signed = self._download(self._upload_pdf().json()["id"], "AES")
        response = self._upload_pdf(data=signed)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(StoredFile.objects.count(), 1)

    def test_wrong_password_signs_nothing(self):
        self._auth(password="not-the-password")
        self.assertEqual(self._upload_pdf().status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(UserKeyPair.objects.filter(purpose=KEY_PURPOSE_SIGNING).exists())
        self.assertFalse(StoredFile.objects.exists())


class SignStoredPdfTests(PdfUploadHelpers):
    """POST /api/files/{id}/sign/ for a PDF stored without a signature."""

    def _sign(self, file_id):
        return self.client.post(f"/api/files/{file_id}/sign/")

    def test_sign_existing_reencrypts_all_three_copies(self):
        file_id = self._upload_pdf(sign=False).json()["id"]
        old_paths = [c.blob.path for c in StoredFile.objects.get(pk=file_id).ciphertexts.all()]

        with self.captureOnCommitCallbacks(execute=True):
            response = self._sign(file_id)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.json()["signed"])
        self.assertEqual(response.json()["original_name"], "lab.pdf")

        copies = {algorithm: self._download(file_id, algorithm) for algorithm in ("AES", "DES", "RC4")}
        self.assertEqual(len(set(copies.values())), 1)
        signed = copies["AES"]
        self.assertTrue(signed.startswith(SAMPLE) and len(signed) > len(SAMPLE))
        self.assertEqual(len(PdfFileReader(BytesIO(signed)).embedded_signatures), 1)
        self.assertEqual(StoredFile.objects.get(pk=file_id).plaintext_size, len(signed))
        self.assertFalse(any(os.path.exists(path) for path in old_paths))  # old copies removed

    def test_sign_twice_409(self):
        file_id = self._upload_pdf(sign=False).json()["id"]
        self._sign(file_id)
        self.assertEqual(self._sign(file_id).status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(PdfSignature.objects.count(), 1)

    def test_sign_non_pdf_record_400(self):
        file_id = self._upload()["id"]  # the base helper uploads fake bytes labelled as a PDF
        response = self._sign(file_id)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(PdfSignature.objects.exists())

    def test_wrong_password_changes_nothing(self):
        file_id = self._upload_pdf(sign=False).json()["id"]
        self._auth(password="not-the-password")
        self.assertEqual(self._sign(file_id).status_code, status.HTTP_403_FORBIDDEN)
        self._auth()
        self.assertEqual(self._download(file_id, "AES"), SAMPLE)

    def test_someone_elses_record_is_404(self):
        file_id = self._upload_pdf(sign=False).json()["id"]
        User.objects.create_user("citra", password=PASSWORD)
        login = self.client.post("/api/auth/login/", {"username": "citra", "password": PASSWORD}, format="json")
        self._auth(access=login.json()["access"])
        self.assertEqual(self._sign(file_id).status_code, status.HTTP_404_NOT_FOUND)


class VerifyPdfTests(SimpleTestCase):
    """verify_pdf: intact, valid, signer, and changes after signing."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = generate_rsa_key_pair()
        cls.owner = build_signing_certificate(cls.key, "alice")
        cls.signed, _ = sign_pdf(SAMPLE, cls.key, cls.owner, "alice")

    def test_verify_valid_signed_pdf(self):
        result = verify_pdf(self.signed, [self.owner])
        self.assertEqual(result.status, "valid")
        self.assertTrue(result.intact and result.valid and result.signer_matches_owner)
        self.assertEqual(result.coverage, "ENTIRE_FILE")
        self.assertFalse(result.modified_after_signing)
        self.assertEqual(result.signer_common_name, "alice")
        self.assertEqual(result.signer_fingerprint, certificate_fingerprint(self.owner))
        self.assertEqual(result.as_dict()["signer"]["common_name"], "alice")

    def test_verify_detects_byte_change_inside_signed_range(self):
        tampered = bytearray(self.signed)
        position = self.signed.index(b"HbA1c 7.1")
        tampered[position + 6] = ord("9")
        result = verify_pdf(bytes(tampered), [self.owner])
        self.assertEqual(result.status, "modified")
        self.assertFalse(result.intact)

    def test_verify_detects_appended_content(self):
        writer = IncrementalPdfFileWriter(BytesIO(self.signed))
        writer.root["/Lang"] = generic.TextStringObject("en")
        writer.update_root()
        out = BytesIO()
        writer.write(out)
        result = verify_pdf(out.getvalue(), [self.owner])
        self.assertEqual(result.status, "modified")
        self.assertTrue(result.intact)  # the signed part itself is unchanged
        self.assertTrue(result.modified_after_signing)
        self.assertEqual(result.coverage, "ENTIRE_REVISION")

    def test_verify_other_users_certificate_is_unknown_signer(self):
        someone_else = build_signing_certificate(generate_rsa_key_pair(), "budi")
        result = verify_pdf(self.signed, [someone_else])
        self.assertEqual(result.status, "unknown_signer")
        self.assertTrue(result.intact and result.valid)
        self.assertFalse(result.signer_matches_owner)

    def test_any_of_the_owners_certificates_counts(self):
        rotated = build_signing_certificate(generate_rsa_key_pair(), "alice")
        self.assertEqual(verify_pdf(self.signed, [rotated, self.owner]).status, "valid")

    def test_verify_unsigned_pdf(self):
        result = verify_pdf(SAMPLE, [self.owner])
        self.assertEqual((result.status, result.signed), ("unsigned", False))
        self.assertIsNone(result.as_dict()["signer"])

    def test_verify_non_pdf_is_refused(self):
        with self.assertRaises(NotAPdf):
            verify_pdf(b"hello", [self.owner])

    def test_openssl_verifies_the_signature_independently(self):
        """Outside pyHanko: openssl checks the CMS over the signed byte ranges."""
        if shutil.which("openssl") is None:
            self.skipTest("openssl is not installed")
        [signature] = PdfFileReader(BytesIO(self.signed)).embedded_signatures
        a, b, c, d = signature.byte_range
        with tempfile.TemporaryDirectory() as tmp:
            paths = {name: os.path.join(tmp, name) for name in ("sig.p7s", "content.bin", "owner.pem")}
            Path(paths["sig.p7s"]).write_bytes(signature.pkcs7_content)
            Path(paths["content.bin"]).write_bytes(self.signed[a : a + b] + self.signed[c : c + d])
            Path(paths["owner.pem"]).write_text(certificate_pem(self.owner))
            result = subprocess.run(
                [
                    "openssl", "cms", "-verify", "-binary", "-inform", "DER",
                    "-in", paths["sig.p7s"], "-content", paths["content.bin"],
                    "-CAfile", paths["owner.pem"], "-purpose", "any", "-out", os.devnull,
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verification successful", result.stderr)
