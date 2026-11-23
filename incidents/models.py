from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models
from django.utils import timezone


class IncidentQuerySet(models.QuerySet):
    """Extra ways to filter lists of incidents."""

    def visible_to(self, user):
        # The same rule as Incident.can_view (below), applied to a whole list
        # at once: the security team sees every incident, a reporter only
        # sees the ones they reported. Used for the incident list page.
        if user.is_security_team:
            return self
        return self.filter(reporter=user)


class Incident(models.Model):
    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Category(models.TextChoices):
        PHISHING = "PHISHING", "Phishing"
        MALWARE = "MALWARE", "Malware"
        UNAUTHORISED_ACCESS = "UNAUTH", "Unauthorised access"
        DATA_LEAK = "DATA_LEAK", "Data leak"
        LOST_DEVICE = "LOST_DEVICE", "Lost or stolen device"
        OTHER = "OTHER", "Other"

    class Status(models.TextChoices):
        OPEN = "OPEN", "Open"
        TRIAGED = "TRIAGED", "Triaged"
        INVESTIGATING = "INVESTIGATING", "Investigating"
        RESOLVED = "RESOLVED", "Resolved"
        CLOSED = "CLOSED", "Closed"

    # The only status changes the app allows. Anything else is rejected,
    # so nobody can jump an incident from OPEN straight to CLOSED.
    ALLOWED_TRANSITIONS = {
        Status.OPEN: {Status.TRIAGED},
        Status.TRIAGED: {Status.INVESTIGATING},
        Status.INVESTIGATING: {Status.RESOLVED},
        Status.RESOLVED: {Status.CLOSED, Status.INVESTIGATING},  # reopen if the fix didn't hold
        Status.CLOSED: set(),  # closed is final
    }

    title = models.CharField(max_length=120)
    description = models.TextField(max_length=5000)
    category = models.CharField(max_length=12, choices=Category.choices, default=Category.OTHER)
    severity = models.CharField(max_length=8, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=13, choices=Status.choices, default=Status.OPEN)

    # PROTECT: deleting a user must never silently delete the incidents they reported.
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="reported_incidents"
    )
    # SET_NULL: if an analyst leaves, the incident stays and becomes unassigned.
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="assigned_incidents",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    # Lets views write Incident.objects.visible_to(request.user).
    objects = IncidentQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]  # newest incidents first

    def __str__(self):
        return f"#{self.pk} {self.title}"

    # ---- Business rules -------------------------------------------------
    # Kept on the model, not in the views, so every view, the admin site
    # and the tests all go through the same checks.

    @property
    def is_locked(self):
        return self.status == self.Status.CLOSED

    def can_view(self, user):
        # Security team sees everything; reporters only see their own (blocks IDOR).
        return user.is_security_team or self.reporter_id == user.id

    def can_edit_details(self, user):
        if self.is_locked:
            return False
        if user.is_security_team:
            return True
        # Reporters can fix typos in their own report until triage starts.
        return self.reporter_id == user.id and self.status == self.Status.OPEN

    def can_change_status(self, user, new_status):
        if self.is_locked or not user.is_security_team:
            return False
        if new_status not in self.ALLOWED_TRANSITIONS[self.status]:
            return False
        # Separation of duties: nobody resolves or closes an incident they reported.
        if new_status in (self.Status.RESOLVED, self.Status.CLOSED) and self.reporter_id == user.id:
            return False
        return True

    def change_status(self, user, new_status):
        if not self.can_change_status(user, new_status):
            raise PermissionDenied("You can't make that status change.")
        self.status = new_status
        if new_status == self.Status.RESOLVED:
            self.resolved_at = timezone.now()
        elif new_status == self.Status.CLOSED:
            self.closed_at = timezone.now()
        self.save()

    def save(self, *args, **kwargs):
        # Defence in depth: even if a view forgets to check, a closed
        # incident can't be written to again.
        if self.pk:
            stored = Incident.objects.filter(pk=self.pk).values_list("status", flat=True).first()
            if stored == self.Status.CLOSED:
                raise ValidationError("Closed incidents are locked and can't be changed.")
        super().save(*args, **kwargs)


class Comment(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="comments")
    body = models.TextField(max_length=3000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def clean(self):
        if self.incident_id and self.incident.is_locked:
            raise ValidationError("You can't comment on a closed incident.")

    def save(self, *args, **kwargs):
        self.clean()  # enforce the lock even when saved outside a form
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Comment by {self.author} on #{self.incident_id}"
