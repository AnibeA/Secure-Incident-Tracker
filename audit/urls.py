# Address for the audit log page: /audit/

from django.urls import path

from .views import audit_log

urlpatterns = [
    path("", audit_log, name="audit_log"),
]
