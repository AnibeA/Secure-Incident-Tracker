# Forms define which incident fields a user can submit, and validate them.

from django import forms

from .models import Incident


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
