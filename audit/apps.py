from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "audit"

    def ready(self):
        # ready() runs once when Django starts. Importing signals here
        # switches on the automatic login/logout/lockout logging.
        from . import signals  # noqa: F401  (imported for its side effect)
