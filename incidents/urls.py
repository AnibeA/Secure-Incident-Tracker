# Addresses for the incidents app. <int:pk> captures the incident's number
# from the address, e.g. /incidents/7/ gives pk=7. "int" means only digits
# are accepted, so /incidents/abc/ never reaches a view.

from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),                                            # "/" -> the incident list
    path("incidents/new/", views.incident_create, name="incident_create"),        # report an incident
    path("incidents/<int:pk>/", views.incident_detail, name="incident_detail"),   # view one incident
    path("incidents/<int:pk>/edit/", views.incident_edit, name="incident_edit"),  # edit one incident
    # Analyst workflow (security team only; both only accept form submissions):
    path("incidents/<int:pk>/status/", views.incident_change_status, name="incident_change_status"),
    path("incidents/<int:pk>/assign/", views.incident_assign, name="incident_assign"),
    # Comments (anyone who can see the incident; form submissions only):
    path("incidents/<int:pk>/comments/", views.comment_add, name="comment_add"),
]
