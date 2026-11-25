# Views for incidents: the list (home page), reporting a new incident,
# viewing one, editing one, and the analyst workflow (status changes and
# assigning). Every view requires a login, every view that touches a single
# incident checks the user may access it, and analyst-only views also check
# the user's role.

from django.contrib import messages                          # one-off messages ("Incident reported")
from django.contrib.auth.decorators import login_required    # blocks anyone not logged in
from django.core.exceptions import PermissionDenied          # raising this returns "403 Forbidden"
from django.core.paginator import Paginator                  # splits long lists into pages
from django.http import Http404                              # raising this returns "404 Not Found"
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST        # refuses anything but a form submission (POST)

from accounts.decorators import security_team_required       # our role check: Analysts and Admins only
from audit.log import record                                 # writes an entry to the audit log
from audit.models import AuditEvent
from .forms import AssignForm, CommentForm, IncidentForm
from .models import Incident


def get_incident_for(request, pk):
    """Fetch one incident, but only if this user is allowed to see it.

    Every view that opens a single incident goes through this one function,
    so the access check (blocking IDOR) can't be forgotten on any page.

    If the user isn't allowed, we answer "404 Not Found", not "403 Forbidden".
    A 403 would confirm the incident exists; a 404 reveals nothing, so an
    attacker can't use the response to discover which incident numbers exist.
    """
    incident = get_object_or_404(Incident, pk=pk)   # 404 if the number doesn't exist at all
    if not incident.can_view(request.user):         # the model's rule (Rule 2 in the study guide)
        # Log the attempt for admins to review (the user still just sees "not found").
        record(request, AuditEvent.Action.ACCESS_DENIED, f"Tried to open incident #{incident.pk}, which isn't theirs")
        raise Http404("Incident not found")         # same answer as "doesn't exist"
    return incident


@login_required
def home(request):
    """The incident list. Reporters see their own; analysts and admins see all."""
    # visible_to() applies the same access rule as can_view(), to the whole list.
    incidents = Incident.objects.visible_to(request.user)

    # Show 20 per page (NFR3), so the page stays fast as incidents pile up.
    # ?page=2 in the address picks the page; anything invalid falls back to page 1.
    page = Paginator(incidents, 20).get_page(request.GET.get("page"))

    return render(request, "incidents/incident_list.html", {"page": page})


@login_required
def incident_create(request):
    """Report a new incident. Anyone logged in can do this."""
    if request.method == "POST":
        # The form was submitted: check what the user typed.
        form = IncidentForm(request.POST)
        if form.is_valid():
            # commit=False builds the incident without saving it yet, so we
            # can set the reporter ourselves. It's always the logged-in user,
            # never a value taken from the request.
            incident = form.save(commit=False)
            incident.reporter = request.user
            incident.save()
            record(request, AuditEvent.Action.INCIDENT_CREATED, f"Incident #{incident.pk}: {incident.title}")
            messages.success(request, "Incident reported.")
            return redirect("incident_detail", pk=incident.pk)
    else:
        # First visit (GET): show an empty form.
        form = IncidentForm()

    # Either a first visit, or the form had errors: show it (with the errors).
    return render(request, "incidents/incident_form.html", {"form": form, "is_new": True})


@login_required
def incident_detail(request, pk):
    """Show one incident, if the user is allowed to see it."""
    incident = get_incident_for(request, pk)   # IDOR check happens here
    context = {
        "incident": incident,
        # Tells the template whether to show the Edit button. Hiding the
        # button is only for convenience; the edit view checks again.
        "can_edit": incident.can_edit_details(request.user),
        # Comments, oldest first. select_related fetches each author in the
        # same database query instead of one extra query per comment.
        "comments": incident.comments.select_related("author"),
        # An empty comment box, unless the incident is closed (then no box).
        "comment_form": None if incident.is_locked else CommentForm(),
    }
    # Only the security team gets the workflow buttons and the assign box.
    if request.user.is_security_team:
        context["next_steps"] = incident.next_steps(request.user)
        # initial= pre-selects whoever is assigned now.
        context["assign_form"] = AssignForm(initial={"assigned_to": incident.assigned_to})
    return render(request, "incidents/incident_detail.html", context)


@login_required
def incident_edit(request, pk):
    """Edit an incident's details, if the rules allow it."""
    incident = get_incident_for(request, pk)   # can they see it at all? (404 if not)

    # They can see it, but can they edit it? Reporters only while it's Open,
    # and nobody once it's Closed. Here 403 is fine: they already know it exists.
    if not incident.can_edit_details(request.user):
        raise PermissionDenied("You can't edit this incident.")

    if request.method == "POST":
        # instance=incident means "update this incident" rather than create a new one.
        form = IncidentForm(request.POST, instance=incident)
        if form.is_valid():
            form.save()
            messages.success(request, "Incident updated.")
            return redirect("incident_detail", pk=incident.pk)
    else:
        # First visit: show the form filled in with the current details.
        form = IncidentForm(instance=incident)

    return render(request, "incidents/incident_form.html", {"form": form, "incident": incident, "is_new": False})


@security_team_required   # role check: Reporters get 403 before anything else happens
@require_POST             # only a submitted form (POST, with its CSRF token) can change status
def incident_change_status(request, pk):
    """Move an incident to its next status (Analysts and Admins only)."""
    incident = get_incident_for(request, pk)
    new_status = request.POST.get("status", "")   # the status the button asked for

    # change_status() applies every rule in the model: the allowed order of
    # statuses, the closed lock, and separation of duties (nobody resolves or
    # closes an incident they reported). If any rule says no, it raises
    # PermissionDenied and the user gets "403 Forbidden"; nothing is saved.
    old_label = incident.get_status_display()          # remember it for the log before it changes
    incident.change_status(request.user, new_status)
    record(request, AuditEvent.Action.STATUS_CHANGED,
           f"Incident #{incident.pk}: {old_label} to {incident.get_status_display()}")

    messages.success(request, f"Status changed to {incident.get_status_display()}.")
    return redirect("incident_detail", pk=incident.pk)


@security_team_required
@require_POST
def incident_assign(request, pk):
    """Assign an incident to an analyst (Analysts and Admins only)."""
    incident = get_incident_for(request, pk)

    # A closed incident is locked: nothing about it can change, including who owns it.
    if incident.is_locked:
        raise PermissionDenied("Closed incidents can't be reassigned.")

    form = AssignForm(request.POST)
    if form.is_valid():
        # cleaned_data holds the checked value: an Analyst/Admin, or None for "Unassigned".
        incident.assigned_to = form.cleaned_data["assigned_to"]
        incident.save()
        assignee = incident.assigned_to.username if incident.assigned_to else "nobody"
        record(request, AuditEvent.Action.ASSIGNED, f"Incident #{incident.pk} assigned to {assignee}")
        messages.success(request, "Assignment updated.")
    else:
        # Someone sent a user who isn't on the security team (or an invalid ID).
        messages.error(request, "That person can't be assigned. Pick an analyst or admin.")
    return redirect("incident_detail", pk=incident.pk)


@login_required
@require_POST   # comments are only ever added by submitting the form
def comment_add(request, pk):
    """Add a comment to an incident the user can see."""
    # The same access check as viewing: you can only comment on incidents
    # you're allowed to see (another reporter's incident gives 404).
    incident = get_incident_for(request, pk)

    # Closed incidents are locked: no new comments either.
    if incident.is_locked:
        raise PermissionDenied("You can't comment on a closed incident.")

    form = CommentForm(request.POST)
    if form.is_valid():
        comment = form.save(commit=False)   # build it, but don't save yet...
        comment.incident = incident         # ...so the server sets which incident
        comment.author = request.user       # ...and who wrote it
        comment.save()
        messages.success(request, "Comment added.")
    else:
        messages.error(request, "Your comment was empty or too long (3,000 characters maximum).")
    # "#comments" scrolls the page straight down to the comments section.
    return redirect(f"{incident.get_absolute_url()}#comments")
