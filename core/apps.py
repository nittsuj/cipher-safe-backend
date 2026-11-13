from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = 'core'

    def ready(self) -> None:
        # Register the signal handlers that delete blobs with their rows.
        from . import signals  # noqa: F401
