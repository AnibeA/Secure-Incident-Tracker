# Forms define which fields a user can submit and validate what they type.

from django import forms                                # Django's form tools
from django.contrib.auth.forms import UserCreationForm  # Django's sign-up form: handles the two
                                                       # password fields, checks they match, and
                                                       # runs the password policy (12+ characters etc.)

from .models import User                               # our custom User model (the one with roles)


class SignUpForm(UserCreationForm):
    class Meta:
        model = User  # create a User from this form

        # Only these fields can be set when signing up. "role" is left out on
        # purpose: even if someone adds role=ADMIN to the request, Django
        # ignores it, so nobody can make themselves an admin (mass assignment).
        # New users therefore always get the default role: Reporter.
        fields = ("username", "email")


class RoleForm(forms.ModelForm):
    """Change one user's role (admins only)."""

    class Meta:
        model = User
        # Only the role can be changed here. The dropdown is limited to the
        # three roles, and the server rejects any other value someone sends.
        fields = ("role",)
