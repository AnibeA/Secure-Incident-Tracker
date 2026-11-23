# URL patterns connect a web address to the view that handles it.
# These are all under /accounts/ (set in config/urls.py), e.g. /accounts/login/.

from django.contrib.auth import views as auth_views  # Django's built-in login and logout views
from django.urls import path                         # path("address/", view, name="...")

from .views import SignUpView                        # our sign-up view

urlpatterns = [
    # /accounts/signup/ shows the sign-up form. name="signup" lets templates
    # link to it with {% url 'signup' %} instead of hard-coding the address.
    path("signup/", SignUpView.as_view(), name="signup"),

    # /accounts/login/ uses Django's login view. It checks the password against
    # the stored Argon2 hash and gives the user a brand-new session ID, which
    # blocks session fixation. redirect_authenticated_user=True sends anyone
    # already logged in straight to the home page instead.
    path("login/", auth_views.LoginView.as_view(redirect_authenticated_user=True), name="login"),

    # /accounts/logout/ ends the session. Django only accepts logout as a POST
    # with a CSRF token, so a malicious link or image on another site can't
    # log you out.
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]
