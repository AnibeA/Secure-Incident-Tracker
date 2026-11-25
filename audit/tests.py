# Tests for the audit log (SR5): the right events are recorded, entries
# can't be changed, and only admins can read the log.

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from incidents.models import Incident
from .models import AuditEvent

PASSWORD = "Correct-Horse-Battery-42"


class AuditTestBase(TestCase):
    def setUp(self):
        self.reporter = User.objects.create_user("rita", password=PASSWORD)
        self.other = User.objects.create_user("otto", password=PASSWORD)
        self.analyst = User.objects.create_user("ana", password=PASSWORD, role=User.Role.ANALYST)
        self.admin = User.objects.create_user("adele", password=PASSWORD, role=User.Role.ADMIN)
        self.incident = Incident.objects.create(title="Phish", description="x", reporter=self.reporter)

    def events(self, action):
        # Helper: all logged events of one kind.
        return AuditEvent.objects.filter(action=action)


class LoginEventTests(AuditTestBase):
    def test_successful_login_is_logged(self):
        self.client.post(reverse("login"), {"username": "rita", "password": PASSWORD})
        event = self.events(AuditEvent.Action.LOGIN).get()
        self.assertEqual(event.actor, self.reporter)
        self.assertEqual(event.ip_address, "127.0.0.1")   # the test client's address

    def test_failed_login_is_logged_without_the_password(self):
        """Failed logins record the username tried, never the password."""
        self.client.post(reverse("login"), {"username": "rita", "password": "guess-number-1"})
        event = self.events(AuditEvent.Action.LOGIN_FAILED).get()
        self.assertEqual(event.username, "rita")
        self.assertNotIn("guess-number-1", event.detail)

    def test_logout_is_logged(self):
        self.client.force_login(self.reporter)
        self.client.post(reverse("logout"))
        self.assertEqual(self.events(AuditEvent.Action.LOGOUT).get().actor, self.reporter)

    def test_lockout_is_logged(self):
        """Brute force leaves a clear trail: 5 failures, then a lockout."""
        for _ in range(6):
            self.client.post(reverse("login"), {"username": "rita", "password": "wrong-password"})
        self.assertGreaterEqual(self.events(AuditEvent.Action.LOGIN_FAILED).count(), 5)
        self.assertTrue(self.events(AuditEvent.Action.LOCKED_OUT).filter(username="rita").exists())


class AccessEventTests(AuditTestBase):
    def test_idor_attempt_is_logged(self):
        """The attacker sees a plain 404, but the attempt is recorded for admins."""
        self.client.force_login(self.other)
        self.client.get(reverse("incident_detail", args=[self.incident.pk]))
        event = self.events(AuditEvent.Action.ACCESS_DENIED).get()
        self.assertEqual(event.actor, self.other)
        self.assertIn(f"#{self.incident.pk}", event.detail)

    def test_forbidden_action_is_logged(self):
        """A reporter forging a status change gets 403, and it's logged."""
        self.client.force_login(self.reporter)
        url = reverse("incident_change_status", args=[self.incident.pk])
        self.assertEqual(self.client.post(url, {"status": "TRIAGED"}).status_code, 403)
        self.assertEqual(self.events(AuditEvent.Action.ACCESS_DENIED).get().actor, self.reporter)


class ActionEventTests(AuditTestBase):
    def test_new_incident_is_logged(self):
        self.client.force_login(self.reporter)
        self.client.post(reverse("incident_create"), {
            "title": "Lost phone", "category": "LOST_DEVICE", "severity": "HIGH", "description": "x",
        })
        self.assertIn("Lost phone", self.events(AuditEvent.Action.INCIDENT_CREATED).get().detail)

    def test_status_change_is_logged_with_before_and_after(self):
        self.client.force_login(self.analyst)
        self.client.post(reverse("incident_change_status", args=[self.incident.pk]), {"status": "TRIAGED"})
        self.assertIn("Open to Triaged", self.events(AuditEvent.Action.STATUS_CHANGED).get().detail)

    def test_assignment_is_logged(self):
        self.client.force_login(self.analyst)
        self.client.post(reverse("incident_assign", args=[self.incident.pk]), {"assigned_to": self.analyst.pk})
        self.assertIn("assigned to ana", self.events(AuditEvent.Action.ASSIGNED).get().detail)

    def test_role_change_is_logged(self):
        self.client.force_login(self.admin)
        self.client.post(reverse("user_change_role", args=[self.other.pk]), {f"user{self.other.pk}-role": "ANALYST"})
        self.assertIn("otto: Reporter to Analyst", self.events(AuditEvent.Action.ROLE_CHANGED).get().detail)


class LogProtectionTests(AuditTestBase):
    def test_entries_cannot_be_edited(self):
        """Append-only: tampering with an entry (to hide an attack) is refused."""
        event = AuditEvent.objects.create(action=AuditEvent.Action.LOGIN, username="rita")
        event.detail = "nothing to see here"
        with self.assertRaises(ValidationError):
            event.save()

    def test_entries_cannot_be_deleted(self):
        event = AuditEvent.objects.create(action=AuditEvent.Action.LOGIN, username="rita")
        with self.assertRaises(ValidationError):
            event.delete()
        self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_only_admins_can_read_the_log(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(reverse("audit_log")).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse("audit_log")).status_code, 200)

    def test_log_page_escapes_typed_usernames(self):
        """A failed login can put any text in the log; the page must show it as text."""
        self.client.post(reverse("login"), {"username": "<script>alert(1)</script>", "password": "x"})
        self.client.force_login(self.admin)
        page = self.client.get(reverse("audit_log")).content.decode()
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;", page)
