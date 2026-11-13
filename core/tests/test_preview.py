from __future__ import annotations

from .base import AuthenticatedApiTestCase


class PreviewTests(AuthenticatedApiTestCase):
    def test_inline_preview_for_safe_types(self):
        body = self._upload()
        response = self.client.get(f"/api/files/{body['id']}/download/?algorithm=AES&inline=1")
        self.assertTrue(response["Content-Disposition"].startswith("inline"))
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")

    def test_html_is_never_served_inline(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        upload = SimpleUploadedFile("x.html", b"<script>alert(1)</script>", content_type="text/html")
        body = self.client.post("/api/files/", {"file": upload, "category": "DOCUMENT"}, format="multipart").json()
        response = self.client.get(f"/api/files/{body['id']}/download/?algorithm=AES&inline=1")
        self.assertTrue(response["Content-Disposition"].startswith("attachment"))
        self.assertEqual(response["Content-Type"], "application/octet-stream")

    def test_ciphertext_download_keeps_the_extension(self):
        body = self._upload()
        response = self.client.get(f"/api/files/{body['id']}/ciphertext/?algorithm=DES")
        self.assertIn('filename="lab-result.DES-encrypted.pdf"', response["Content-Disposition"])
