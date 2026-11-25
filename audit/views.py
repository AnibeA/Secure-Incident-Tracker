# The Audit log page: a read-only list of events, for admins only.
# There's deliberately no view to edit or delete entries.

from django.core.paginator import Paginator
from django.shortcuts import render

from accounts.decorators import admin_required   # our role check: Admins only
from .log import record
from .models import AuditEvent


@admin_required
def audit_log(request):
    # select_related fetches each event's user in the same database query.
    events = AuditEvent.objects.select_related("actor")
    # 50 per page; ?page=2 picks the page, invalid values fall back to page 1.
    page = Paginator(events, 50).get_page(request.GET.get("page"))
    return render(request, "audit/audit_log.html", {"page": page})


def permission_denied(request, exception=None):
    """Runs whenever any view refuses access with 403 (set in config/urls.py).

    Every refusal is logged before the user sees the "not allowed" page, so a
    reporter trying analyst-only actions, or an analyst trying to resolve
    their own incident, leaves a trace an admin can review.
    """
    reason = str(exception) if exception else ""
    record(request, AuditEvent.Action.ACCESS_DENIED, f"{request.method} {request.path} {reason}".strip())
    return render(request, "403.html", status=403)
