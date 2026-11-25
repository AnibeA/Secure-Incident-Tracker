# Signals let us react to things Django and django-axes already do, without
# changing their code. Here: every login, failed login, logout and lockout
# is written to the audit log automatically.

from axes.signals import user_locked_out
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .log import record
from .models import AuditEvent


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    record(request, AuditEvent.Action.LOGIN, user=user)


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    # credentials holds what was typed. Django has already replaced the
    # password with asterisks, so passwords never reach the log.
    record(request, AuditEvent.Action.LOGIN_FAILED, username=credentials.get("username", ""))


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    # user can be None if the session had already expired.
    if user is not None:
        record(request, AuditEvent.Action.LOGOUT, user=user)


@receiver(user_locked_out)
def on_locked_out(sender, request, username, ip_address, **kwargs):
    # Sent by django-axes when the lockout (5 failures) kicks in.
    record(request, AuditEvent.Action.LOCKED_OUT, detail="Too many failed logins", username=username or "")
