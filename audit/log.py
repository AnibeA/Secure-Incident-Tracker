# One function the rest of the app calls to write an audit entry:
#     record(request, AuditEvent.Action.STATUS_CHANGED, "Incident #7: Open to Triaged")
# Keeping it in one place means every entry is recorded the same way.

from .models import AuditEvent


def client_ip(request):
    """The IP address the request came from.

    We use REMOTE_ADDR, the address of whoever actually connected. We
    deliberately don't trust the X-Forwarded-For header, because any client
    can type whatever they like into it and fake their address in the log.
    (Behind a real proxy server, it would need configuring for that proxy.)
    """
    return request.META.get("REMOTE_ADDR") if request is not None else None


def record(request, action, detail="", user=None, username=""):
    """Write one audit entry.

    user defaults to whoever is logged in on this request. username lets us
    record a name that was typed but isn't (or isn't yet) logged in, such as
    the target of a failed login.
    """
    if user is None and request is not None and request.user.is_authenticated:
        user = request.user
    return AuditEvent.objects.create(
        actor=user,
        username=(username or (user.username if user else ""))[:150],   # [:150] keeps it within the column size
        action=action,
        detail=detail[:255],
        ip_address=client_ip(request),
    )
