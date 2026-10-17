from __future__ import annotations

from rest_framework import status

from ..crypto import SUPPORTED_ALGORITHMS

from .base import PASSWORD, AuthenticatedApiTestCase


class FileApiTests(AuthenticatedApiTestCase):
    def test_upload_stores_one_ciphertext_per_algorithm(self):
        body = self._upload()
        algorithms = {ciphertext["algorithm"] for ciphertext in body["ciphertexts"]}
        self.assertEqual(algorithms, set(SUPPORTED_ALGORITHMS))

    def test_download_matches_original_for_every_algorithm(self):
        content = b"fake document payload " * 200
        body = self._upload(content)
        for algorithm in SUPPORTED_ALGORITHMS:
            response = self.client.get(
                f"/api/files/{body['id']}/download/?algorithm={algorithm}"
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.content, content)

    def test_download_supports_cfb_mode(self):
        content = b"cfb payload " * 50
        body = self._upload(content, mode="CFB")
        response = self.client.get(f"/api/files/{body['id']}/download/?algorithm=AES")
        self.assertEqual(response.content, content)

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
