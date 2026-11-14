from __future__ import annotations

from rest_framework import status

from .base import AuthenticatedApiTestCase


class RetiredShareKeyTests(AuthenticatedApiTestCase):
    """The old doctor share-key endpoints are gone; sharing goes through access requests."""

    def test_old_share_urls_return_404(self):
        file_id = self._upload()["id"]
        calls = [
            ("get", f"/api/files/{file_id}/shares/"),
            ("post", f"/api/files/{file_id}/shares/"),
            ("delete", "/api/shares/1/"),
            ("get", "/api/shares/received/"),
            ("get", "/api/shares/received/1/open/"),
        ]
        for method, url in calls:
            with self.subTest(method=method, url=url):
                self.assertEqual(getattr(self.client, method)(url).status_code, status.HTTP_404_NOT_FOUND)
