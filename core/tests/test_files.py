from __future__ import annotations

import os

from rest_framework import status

from django.core.files.uploadedfile import SimpleUploadedFile

from ..crypto import MODE_FOR, SUPPORTED_ALGORITHMS
from ..models import FileCiphertext, FileLabel, StoredFile

from .base import PASSWORD, AuthenticatedApiTestCase


class FileApiTests(AuthenticatedApiTestCase):
    def test_upload_stores_one_ciphertext_per_algorithm(self):
        body = self._upload()
        algorithms = {ciphertext["algorithm"] for ciphertext in body["ciphertexts"]}
        self.assertEqual(algorithms, set(SUPPORTED_ALGORITHMS))

    def test_download_matches_original_for_every_algorithm(self):
        content = b"fake lab result payload " * 200
        body = self._upload(content)
        for algorithm in SUPPORTED_ALGORITHMS:
            response = self.client.get(
                f"/api/files/{body['id']}/download/?algorithm={algorithm}"
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.content, content)

    def test_files_use_the_chosen_mode_per_algorithm(self):
        body = self._upload()
        modes = {c["algorithm"]: c["mode"] for c in body["ciphertexts"]}
        self.assertEqual(modes, MODE_FOR)

    def test_tampered_blob_is_refused_not_returned(self):
        content = b"ultrasound frame " * 100
        body = self._upload(content, category="VIDEO")
        for algorithm in SUPPORTED_ALGORITHMS:
            row = FileCiphertext.objects.get(file_id=body["id"], algorithm=algorithm)
            path = row.blob.path
            with open(path, "r+b") as handle:
                first = handle.read(1)
                handle.seek(0)
                handle.write(bytes([first[0] ^ 0x01]))
            response = self.client.get(f"/api/files/{body['id']}/download/?algorithm={algorithm}")
            self.assertEqual(response.status_code, status.HTTP_409_CONFLICT, algorithm)

    def test_file_name_is_encrypted_but_returned_to_the_owner(self):
        body = self._upload()
        self.assertEqual(body["original_name"], "lab-result.pdf")
        self.assertFalse(hasattr(StoredFile.objects.get(pk=body["id"]), "original_name"))
        labels = FileLabel.objects.filter(file_id=body["id"])
        self.assertEqual({label.algorithm for label in labels}, set(SUPPORTED_ALGORITHMS))
        for label in labels:
            self.assertNotIn(b"lab-result", bytes(label.ciphertext))

        listed = self.client.get("/api/files/").json()
        self.assertEqual(listed[0]["original_name"], "lab-result.pdf")
        self.assertEqual(listed[0]["content_type"], "application/pdf")
        for algorithm in SUPPORTED_ALGORITHMS:
            response = self.client.get(f"/api/files/{body['id']}/download/?algorithm={algorithm}")
            self.assertIn("lab-result.pdf", response["Content-Disposition"])
        history = self.client.get("/api/analysis/downloads/").json()
        self.assertEqual(history[0]["original_name"], "lab-result.pdf")

    def test_ciphertext_download_returns_the_stored_bytes(self):
        content = b"fake lab result payload " * 200
        body = self._upload(content)
        copies = set()
        for algorithm in SUPPORTED_ALGORITHMS:
            response = self.client.get(f"/api/files/{body['id']}/ciphertext/?algorithm={algorithm}")
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertNotEqual(response.content, content)
            self.assertEqual(len(response.content), len(content))  # CTR and RC4 add no padding
            copies.add(response.content)
        self.assertEqual(len(copies), len(SUPPORTED_ALGORITHMS))

    def test_listing_requires_the_password(self):
        self._upload()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        self.assertEqual(self.client.get("/api/files/").status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_removes_ciphertext_blobs(self):
        body = self._upload()
        paths = [row.blob.path for row in FileCiphertext.objects.filter(file_id=body["id"])]
        self.assertTrue(all(os.path.exists(path) for path in paths))
        response = self.client.delete(f"/api/files/{body['id']}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(any(os.path.exists(path) for path in paths))

    def test_old_upload_mode_field_is_ignored(self):
        upload = SimpleUploadedFile("scan.png", b"png bytes", content_type="image/png")
        response = self.client.post(
            "/api/files/", {"file": upload, "category": "ID_CARD", "mode": "CBC"}, format="multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual({c["mode"] for c in response.json()["ciphertexts"]}, set(MODE_FOR.values()))

    def test_other_users_cannot_access_a_file(self):
        body = self._upload()
        self.client.post(
            "/api/auth/register/",
            {"username": "bob", "password": PASSWORD},
            format="json",
        )
        other = self.client.post(
            "/api/auth/login/",
            {"username": "bob", "password": PASSWORD},
            format="json",
        )
        self._auth(access=other.json()["access"])
        self.assertEqual(
            self.client.get(f"/api/files/{body['id']}/").status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertEqual(
            self.client.get(f"/api/files/{body['id']}/download/?algorithm=AES").status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_benchmark_and_timing_endpoints(self):
        body = self._upload()
        self.client.get(f"/api/files/{body['id']}/download/?algorithm=AES")
        benchmark = self.client.get(f"/api/files/{body['id']}/benchmark/?algorithm=DES&runs=3")
        self.assertEqual(benchmark.status_code, status.HTTP_200_OK)
        self.assertEqual(benchmark.json()["runs"], 3)

        timings = self.client.get("/api/analysis/timings/")
        self.assertEqual(timings.status_code, status.HTTP_200_OK)
        self.assertIn("downloads", timings.json())
