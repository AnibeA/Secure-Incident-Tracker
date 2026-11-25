# Views are the functions/classes that handle a web request and return a page.
# This file has the sign-up view and the admin's user-management views.
# Login and logout use Django's built-in views (see accounts/urls.py),
# which are already well tested.

from django.contrib import messages             # one-off messages shown on the next page ("Account created")
from django.core.exceptions import PermissionDenied  # raising this returns "403 Forbidden"
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST  # refuses anything but a form submission (POST)
from django.urls import reverse_lazy            # turns a URL name like "login" into the actual address
from django.views.generic import CreateView     # a ready-made view that shows a form and saves a new object

from audit.log import record                    # writes an entry to the audit log
from audit.models import AuditEvent

from .decorators import admin_required          # our role check: Admins only
from .forms import RoleForm, SignUpForm         # sign-up form, and the admin's change-role form
from .models import User


class SignUpView(CreateView):
    # CreateView does the heavy lifting: on GET it shows an empty form,
    # on POST it validates the form and, if valid, saves the new user.
    form_class = SignUpForm                     # which form to use
    template_name = "accounts/signup.html"      # which HTML template displays it
    success_url = reverse_lazy("login")         # where to send the user after signing up

    def form_valid(self, form):
        # Runs only when the form passed every check (passwords match,
        # password policy met, username not taken). We add a friendly
        # message, then let CreateView save the user and redirect.
        messages.success(self.request, "Account created. You can now log in.")
        return super().form_valid(form)


@admin_required   # Reporters and Analysts get 403
def user_list(request):
    """List every user with a role dropdown next to each (admins only)."""
    users = User.objects.order_by("username")
    # Pair each user with a form already set to their current role.
    rows = [(u, RoleForm(instance=u, prefix=f"user{u.pk}")) for u in users]
    return render(request, "accounts/user_list.html", {"rows": rows})


@admin_required
@require_POST     # roles only change through a submitted form with a CSRF token
def user_change_role(request, pk):
    """Change one user's role (admins only)."""
    target = get_object_or_404(User, pk=pk)

    # You can't change your own role. This stops an admin accidentally
    # demoting themselves and leaving nobody able to manage users.
    if target == request.user:
        raise PermissionDenied("You can't change your own role.")

    # The superuser made with createsuperuser is always an Admin (see
    # User.save), so its role can't be changed from this page.
    if target.is_superuser:
        raise PermissionDenied("The main admin account's role can't be changed here.")

    # prefix must match the one used in user_list, so the field names line up.
    old_role = target.get_role_display()   # remember it for the log before it changes
    form = RoleForm(request.POST, instance=target, prefix=f"user{target.pk}")
    if form.is_valid():
        form.save()
        record(request, AuditEvent.Action.ROLE_CHANGED,
               f"{target.username}: {old_role} to {target.get_role_display()}")
        messages.success(request, f"{target.username} is now {target.get_role_display()}.")
    else:
        messages.error(request, "That isn't a valid role.")
    return redirect("user_list")
