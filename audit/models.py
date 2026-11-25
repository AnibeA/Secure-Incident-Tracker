# The audit log: a permanent record of security-relevant events (SR5).
# Each row says who did what, to what, from where, and when.

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class AuditEvent(models.Model):
    class Action(models.TextChoices):
        # The kinds of event we record. Fixed list, so reports stay consistent.
        LOGIN = "LOGIN", "Logged in"
        LOGIN_FAILED = "LOGIN_FAILED", "Failed login"
        LOCKED_OUT = "LOCKED_OUT", "Locked out"
        LOGOUT = "LOGOUT", "Logged out"
        ACCESS_DENIED = "ACCESS_DENIED", "Access denied"
        INCIDENT_CREATED = "INCIDENT_CREATED", "Incident reported"
        STATUS_CHANGED = "STATUS_CHANGED", "Status changed"
        ASSIGNED = "ASSIGNED", "Incident assigned"
        ROLE_CHANGED = "ROLE_CHANGED", "Role changed"

    timestamp = models.DateTimeField(auto_now_add=True)   # set by the server; can't be faked

    # Who did it. SET_NULL keeps the log entry even if the account is later
    # deleted; null for events with no logged-in user (e.g. a failed login).
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="audit_events",
    )
    # The username as typed or as it was at the time. For failed logins this
    # is the name someone TRIED, which shows targeted guessing.
    username = models.CharField(max_length=150, blank=True)

    action = models.CharField(max_length=20, choices=Action.choices)
    detail = models.CharField(max_length=255, blank=True)   # e.g. "Incident #7: Open to Triaged"
    ip_address = models.GenericIPAddressField(null=True, blank=True)   # where the request came from

    class Meta:
        ordering = ["-timestamp"]   # newest first

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M} {self.username or '-'} {self.action}"

    # ---- Append-only ---------------------------------------------------------
    # An audit log is only trustworthy if nobody can quietly change it, so
    # entries can be added but never edited or deleted through the app.
    # (Known limit: someone with direct access to the database file could
    # still change it. Production systems also ship logs to a separate server.)

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValidationError("Audit entries can't be changed.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Audit entries can't be deleted.")
