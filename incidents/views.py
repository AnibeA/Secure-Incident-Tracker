# Views for the incidents app. For now there's only the home page;
# reporting, viewing and managing incidents come next in Phase 3.

from django.contrib.auth.decorators import login_required  # blocks anyone who isn't logged in
from django.shortcuts import render                         # fills in a template and returns it as a page


@login_required  # not logged in? You're redirected to the login page instead.
def home(request):
    # request.user is the logged-in user; the template uses it to show
    # their username and role.
    return render(request, "home.html")
