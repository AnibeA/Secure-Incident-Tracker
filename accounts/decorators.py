# Role checks you can put on top of any view, just like @login_required.
# Each one first makes sure the user is logged in, then checks their role.
# The wrong role gets "403 Forbidden".
#
# Keeping each role check in one place means it's written once and can't
# be written slightly differently (or forgotten) on some page.

from functools import wraps                                  # keeps the original view's name and details

from django.contrib.auth.decorators import login_required    # sends anonymous visitors to the login page
from django.core.exceptions import PermissionDenied          # raising this returns "403 Forbidden"


def security_team_required(view_func):
    """Only Analysts and Admins may use this view."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # is_security_team is defined on our User model: True for Analysts and Admins.
        if not request.user.is_security_team:
            raise PermissionDenied("Analysts and admins only.")
        return view_func(request, *args, **kwargs)   # allowed: run the real view

    # login_required wraps the outside, so the login check always runs first.
    return login_required(wrapper)


def admin_required(view_func):
    """Only Admins may use this view."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_admin_role:
            raise PermissionDenied("Admins only.")
        return view_func(request, *args, **kwargs)

    return login_required(wrapper)
