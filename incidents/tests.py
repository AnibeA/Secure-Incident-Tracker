# Automated tests for reporting and viewing incidents.
# Run them with: python manage.py test
# Each test starts with a fresh, empty test database, built by setUp() below.

from django.test import Client, TestCase   # TestCase = test class; Client = a fake browser
from django.urls import reverse            # turns a URL name into its address

from accounts.models import User
from .models import Incident


class IncidentTestBase(TestCase):
    """Shared starting point: two reporters, one analyst, and one incident."""

    def setUp(self):
        # setUp() runs before every single test, so each starts the same way.
        self.alice = User.objects.create_user("alice", password="x")   # reporter
        self.bob = User.objects.create_user("bob", password="x")       # another reporter
        self.analyst = User.objects.create_user("ana", password="x", role=User.Role.ANALYST)
        # An incident reported by alice.
        self.incident = Incident.objects.create(
            title="Phishing email", description="Clicked a link", reporter=self.alice
        )

    def detail_url(self, incident=None):
        # Helper: the address of an incident's page, e.g. /incidents/1/
        return reverse("incident_detail", args=[(incident or self.incident).pk])


class ReportingTests(IncidentTestBase):
    def test_reporter_is_set_by_the_server(self):
        """The new incident belongs to whoever is logged in."""
        self.client.force_login(self.bob)      # log in as bob without typing a password
        self.client.post(reverse("incident_create"), {
            "title": "Lost laptop", "category": "LOST_DEVICE", "severity": "HIGH",
            "description": "Left on the train",
        })
        self.assertEqual(Incident.objects.get(title="Lost laptop").reporter, self.bob)

    def test_cannot_set_status_or_reporter_when_reporting(self):
        """Mass assignment: extra fields in the request are ignored."""
        self.client.force_login(self.bob)
        self.client.post(reverse("incident_create"), {
            "title": "Sneaky", "category": "OTHER", "severity": "LOW", "description": "x",
            "status": "CLOSED", "reporter": self.alice.pk,   # an attacker adds these
        })
        incident = Incident.objects.get(title="Sneaky")
        self.assertEqual(incident.status, Incident.Status.OPEN)  # not CLOSED
        self.assertEqual(incident.reporter, self.bob)            # not alice

    def test_invalid_choice_is_rejected(self):
        """Input validation: a severity outside the fixed list isn't accepted."""
        self.client.force_login(self.bob)
        self.client.post(reverse("incident_create"), {
            "title": "Bad", "category": "OTHER", "severity": "APOCALYPTIC", "description": "x",
        })
        self.assertFalse(Incident.objects.filter(title="Bad").exists())


class AccessTests(IncidentTestBase):
    def test_reporter_sees_own_incident(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self.detail_url()).status_code, 200)

    def test_other_reporter_gets_404_idor(self):
        """IDOR (misuse case MC1): bob guesses alice's incident number and gets "not found"."""
        self.client.force_login(self.bob)
        self.assertEqual(self.client.get(self.detail_url()).status_code, 404)

    def test_analyst_sees_any_incident(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(self.detail_url()).status_code, 200)

    def test_list_only_shows_own_incidents_to_reporters(self):
        """The home page list is filtered too, not just the detail page."""
        Incident.objects.create(title="Bob's incident", description="x", reporter=self.bob)
        self.client.force_login(self.alice)
        page = self.client.get(reverse("home")).content.decode()
        self.assertIn("Phishing email", page)
        self.assertNotIn("Bob&#x27;s incident", page)   # Django escapes the apostrophe
        self.assertNotIn("Bob's incident", page)

    def test_must_be_logged_in(self):
        """Anonymous visitors are sent to the login page."""
        response = self.client.get(self.detail_url())
        self.assertEqual(response.status_code, 302)               # 302 = redirect
        self.assertIn(reverse("login"), response["Location"])


class EditingTests(IncidentTestBase):
    def test_reporter_can_edit_while_open(self):
        self.client.force_login(self.alice)
        url = reverse("incident_edit", args=[self.incident.pk])
        self.client.post(url, {"title": "Phishing email (updated)", "category": "PHISHING",
                               "severity": "HIGH", "description": "More detail"})
        self.incident.refresh_from_db()                           # reload from the database
        self.assertEqual(self.incident.title, "Phishing email (updated)")

    def test_reporter_cannot_edit_after_triage(self):
        """Once an analyst has triaged it, the reporter's edit page is refused (403)."""
        self.incident.change_status(self.analyst, Incident.Status.TRIAGED)
        self.client.force_login(self.alice)
        url = reverse("incident_edit", args=[self.incident.pk])
        self.assertEqual(self.client.get(url).status_code, 403)

    def test_other_reporter_cannot_reach_edit_page(self):
        """IDOR on the edit page too: 404, same as the detail page."""
        self.client.force_login(self.bob)
        url = reverse("incident_edit", args=[self.incident.pk])
        self.assertEqual(self.client.get(url).status_code, 404)


class InjectionTests(IncidentTestBase):
    def test_script_in_description_is_escaped_xss(self):
        """Stored XSS (misuse case MC5): a <script> typed into an incident shows as text."""
        self.incident.description = "<script>alert('hacked')</script>"
        self.incident.save()
        self.client.force_login(self.analyst)
        page = self.client.get(self.detail_url()).content.decode()
        self.assertNotIn("<script>alert", page)          # the raw tag is NOT in the page
        self.assertIn("&lt;script&gt;", page)            # it's there as harmless text

    def test_sql_injection_in_title_is_stored_as_text(self):
        """SQL injection: SQL typed into a field is saved as plain text, never run."""
        self.client.force_login(self.bob)
        payload = "x'); DROP TABLE incidents_incident; --"
        self.client.post(reverse("incident_create"), {
            "title": payload, "category": "OTHER", "severity": "LOW", "description": "x",
        })
        self.assertTrue(Incident.objects.filter(title=payload).exists())   # stored as text
        self.assertEqual(Incident.objects.count(), 2)                      # table still intact

    def test_form_without_csrf_token_is_rejected(self):
        """CSRF (misuse case MC7): a form posted without a valid token gets 403."""
        csrf_client = Client(enforce_csrf_checks=True)   # a fake browser that checks CSRF like a real one
        csrf_client.force_login(self.bob)
        response = csrf_client.post(reverse("incident_create"), {
            "title": "Forged", "category": "OTHER", "severity": "LOW", "description": "x",
        })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Incident.objects.filter(title="Forged").exists())
