"""Delete the shared copies and keys of access that has ended.

Expired items are already refused by the API; this removes the data. Run it
regularly, e.g. from cron: ``python manage.py purge_expired_grants``.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from core.services import purge_expired_grants


class Command(BaseCommand):
    help = "Delete granted copies and keys whose access period has ended."

    def handle(self, *args, **options):
        count = purge_expired_grants()
        self.stdout.write(f"Deleted {count} expired granted item(s).")
