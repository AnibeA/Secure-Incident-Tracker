# Forms define which incident fields a user can submit, and validate them.

from django import forms

from accounts.models import User
from .models import Comment, Incident


class IncidentForm(forms.ModelForm):
    # A ModelForm builds its fields from the Incident model, so the model's
    # limits apply automatically: max lengths on title and description, and
    # only the allowed values for category and severity (fixed lists).

    class Meta:
        model = Incident

        # Only these four fields can be filled in by the user. Everything
        # else is set by the server, never by the browser:
        #   - reporter: always the logged-in user (set in the view)
        #   - status: always starts as Open, and only changes through the workflow
        #   - assigned_to, timestamps: set by analysts or automatically
        # So even if someone adds status=CLOSED or reporter=<someone else>
        # to the request, Django ignores it (blocks mass assignment).
        fields = ("title", "category", "severity", "description")

        # Show the description as a large text box instead of a one-line input.
        widgets = {"description": forms.Textarea(attrs={"rows": 6})}


class AssignForm(forms.Form):
    """Pick which analyst handles an incident (security team only)."""

    # The dropdown only offers Analysts and Admins. If someone edits the
    # request to send a reporter's ID instead, the form rejects it, because
    # that ID isn't in this list (validation on the server, not the browser).
    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.filter(role__in=[User.Role.ANALYST, User.Role.ADMIN]).order_by("username"),
        required=False,                 # leaving it empty means "Unassigned"
        empty_label="Unassigned",
        label="Assigned to",
    )


class CommentForm(forms.ModelForm):
    """Add a comment to an incident."""

    class Meta:
        model = Comment
        # Only the text can be submitted. The incident and the author are set
        # by the server (the incident from the address, the author from the
        # logged-in user), so nobody can post a comment as someone else or
        # onto an incident they can't see (blocks mass assignment).
        fields = ("body",)
        labels = {"body": "Add a comment"}
        widgets = {"body": forms.Textarea(attrs={"rows": 3})}
