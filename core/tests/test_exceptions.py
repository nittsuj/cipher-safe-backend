from __future__ import annotations

from django.test import SimpleTestCase
from rest_framework import status

from ..crypto import IntegrityError
from ..exceptions import exception_handler


class ExceptionHandlerTests(SimpleTestCase):
    def test_integrity_error_becomes_409(self):
        response = exception_handler(IntegrityError("tag mismatch"), {})
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["detail"].code, "integrity_check_failed")

    def test_other_exceptions_are_left_to_drf(self):
        self.assertIsNone(exception_handler(ValueError("not an API error"), {}))
