# The project's main URL list. Every request starts here, and Django
# checks these patterns top to bottom until one matches the address.

from django.contrib import admin           # Django's built-in admin site
from django.urls import include, path      # include() hands a whole section of addresses to an app

from incidents.views import home           # the home page view

urlpatterns = [
    path("", home, name="home"),                    # "/" -> the home page (login required)
    path("accounts/", include("accounts.urls")),    # "/accounts/..." -> sign-up, login, logout
    path("admin/", admin.site.urls),                # "/admin/" -> Django's admin site
]
