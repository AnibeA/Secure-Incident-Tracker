from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom user with an explicit role.

    Defined before the first migration on purpose: Django can't cleanly
    swap the user model once the database exists.
    """

    class Role(models.TextChoices):
        REPORTER = "REPORTER", "Reporter"  # any staff member who reports an incident
        ANALYST = "ANALYST", "Analyst"     # security team: triages and investigates
        ADMIN = "ADMIN", "Admin"           # manages users and roles

    # Least privilege: everyone who signs up is a reporter.
    # Only an admin can promote someone to analyst or admin.
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.REPORTER)

    @property
    def is_reporter(self):
        return self.role == self.Role.REPORTER

    @property
    def is_analyst(self):
        return self.role == self.Role.ANALYST

    @property
    def is_admin_role(self):
        return self.role == self.Role.ADMIN

    @property
    def is_security_team(self):
        """Analysts and admins can see every incident."""
        return self.role in (self.Role.ANALYST, self.Role.ADMIN)