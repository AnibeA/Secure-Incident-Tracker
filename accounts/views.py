# Views are the functions/classes that handle a web request and return a page.
# This file only needs a sign-up view: login and logout use Django's built-in
# views (see accounts/urls.py), which are already well tested.

from django.contrib import messages             # one-off messages shown on the next page ("Account created")
from django.urls import reverse_lazy            # turns a URL name like "login" into the actual address
from django.views.generic import CreateView     # a ready-made view that shows a form and saves a new object

from .forms import SignUpForm                   # our own sign-up form (only allows username, email, password)


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
