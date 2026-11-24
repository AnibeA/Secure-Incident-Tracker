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


class WorkflowTests(IncidentTestBase):
    """The analyst workflow: role checks, status order, separation of duties, the closed lock."""

    def status_url(self, incident=None):
        # Helper: the address that changes an incident's status.
        return reverse("incident_change_status", args=[(incident or self.incident).pk])

    def assign_url(self):
        return reverse("incident_assign", args=[self.incident.pk])

    def move(self, user, status):
        # Helper: log in as `user` and press the "Move to <status>" button.
        self.client.force_login(user)
        return self.client.post(self.status_url(), {"status": status})

    def test_analyst_can_triage(self):
        self.move(self.analyst, "TRIAGED")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.TRIAGED)

    def test_reporter_cannot_change_status(self):
        """Role check: a reporter crafting the request by hand gets 403."""
        response = self.move(self.alice, "TRIAGED")
        self.assertEqual(response.status_code, 403)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.OPEN)   # unchanged

    def test_cannot_skip_straight_to_closed(self):
        """Workflow order: Open can only go to Triaged."""
        response = self.move(self.analyst, "CLOSED")
        self.assertEqual(response.status_code, 403)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.OPEN)

    def test_status_change_only_accepts_post(self):
        """A plain link (GET) can't change status; only a form with a CSRF token can."""
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(self.status_url()).status_code, 405)   # 405 = method not allowed

    def test_analyst_cannot_resolve_own_incident(self):
        """Separation of duties (misuse case MC2): reporting and resolving need two different people."""
        own = Incident.objects.create(title="Mine", description="x", reporter=self.analyst)
        own.change_status(self.analyst, Incident.Status.TRIAGED)
        own.change_status(self.analyst, Incident.Status.INVESTIGATING)
        self.client.force_login(self.analyst)
        response = self.client.post(self.status_url(own), {"status": "RESOLVED"})
        self.assertEqual(response.status_code, 403)
        own.refresh_from_db()
        self.assertEqual(own.status, Incident.Status.INVESTIGATING)    # not resolved

        # A different analyst can resolve it.
        second = User.objects.create_user("sam", password="x", role=User.Role.ANALYST)
        self.client.force_login(second)
        self.client.post(self.status_url(own), {"status": "RESOLVED"})
        own.refresh_from_db()
        self.assertEqual(own.status, Incident.Status.RESOLVED)

    def test_page_explains_separation_of_duties(self):
        """The reporting analyst sees the step disabled, with the reason."""
        own = Incident.objects.create(title="Mine", description="x", reporter=self.analyst)
        own.change_status(self.analyst, Incident.Status.TRIAGED)
        own.change_status(self.analyst, Incident.Status.INVESTIGATING)
        self.client.force_login(self.analyst)
        page = self.client.get(self.detail_url(own)).content.decode()
        self.assertIn("another analyst has to mark it resolved", page)

    def close(self):
        # Helper: take the incident all the way to Closed, as a second analyst.
        closer = User.objects.create_user("cara", password="x", role=User.Role.ANALYST)
        for status in ["TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED"]:
            self.incident.change_status(closer, status)

    def test_closed_incident_is_locked(self):
        """Closed lock (misuse case MC3): no edits, no status changes, no reassigning."""
        self.close()
        self.client.force_login(self.analyst)
        edit_url = reverse("incident_edit", args=[self.incident.pk])
        self.assertEqual(self.client.get(edit_url).status_code, 403)
        self.assertEqual(self.client.post(self.status_url(), {"status": "INVESTIGATING"}).status_code, 403)
        self.assertEqual(self.client.post(self.assign_url(), {"assigned_to": self.analyst.pk}).status_code, 403)

    def test_analyst_can_assign_to_analyst(self):
        self.client.force_login(self.analyst)
        self.client.post(self.assign_url(), {"assigned_to": self.analyst.pk})
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.assigned_to, self.analyst)

    def test_cannot_assign_to_a_reporter(self):
        """Input validation: the form only accepts Analysts and Admins as assignees."""
        self.client.force_login(self.analyst)
        self.client.post(self.assign_url(), {"assigned_to": self.bob.pk})   # bob is a reporter
        self.incident.refresh_from_db()
        self.assertIsNone(self.incident.assigned_to)

    def test_reporter_cannot_assign(self):
        """Role check on the assign view too."""
        self.client.force_login(self.alice)
        self.assertEqual(self.client.post(self.assign_url(), {"assigned_to": self.analyst.pk}).status_code, 403)


class CommentTests(IncidentTestBase):
    """Comments: same access rules as viewing, the closed lock, and escaping."""

    def comment_url(self):
        return reverse("comment_add", args=[self.incident.pk])

    def test_reporter_can_comment_on_own_incident(self):
        self.client.force_login(self.alice)
        self.client.post(self.comment_url(), {"body": "Any update?"})
        comment = self.incident.comments.get()             # exactly one comment
        self.assertEqual(comment.author, self.alice)        # author set by the server

    def test_cannot_comment_on_someone_elses_incident(self):
        """IDOR on comments: bob can't post on alice's incident (404, nothing saved)."""
        self.client.force_login(self.bob)
        response = self.client.post(self.comment_url(), {"body": "Sneaky"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.incident.comments.count(), 0)

    def test_cannot_post_as_someone_else(self):
        """Mass assignment: an author field in the request is ignored."""
        self.client.force_login(self.alice)
        self.client.post(self.comment_url(), {"body": "Hi", "author": self.analyst.pk})
        self.assertEqual(self.incident.comments.get().author, self.alice)

    def test_cannot_comment_on_closed_incident(self):
        """Closed lock covers comments too (403, nothing saved)."""
        closer = User.objects.create_user("cara", password="x", role=User.Role.ANALYST)
        for status in ["TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED"]:
            self.incident.change_status(closer, status)
        self.client.force_login(self.alice)
        self.assertEqual(self.client.post(self.comment_url(), {"body": "Late"}).status_code, 403)
        self.assertEqual(self.incident.comments.count(), 0)

    def test_script_in_comment_is_escaped(self):
        """Stored XSS in comments: shown as text, never run."""
        self.client.force_login(self.alice)
        self.client.post(self.comment_url(), {"body": "<script>alert(1)</script>"})
        self.client.force_login(self.analyst)
        page = self.client.get(self.detail_url()).content.decode()
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;", page)


class NoLeakTests(IncidentTestBase):
    def test_hidden_incident_looks_exactly_like_a_missing_one(self):
        """IDOR, no leaks: bob gets the identical page for alice's incident and for a number that doesn't exist."""
        self.client.force_login(self.bob)
        hidden = self.client.get(self.detail_url())                                   # exists, but not his
        missing = self.client.get(reverse("incident_detail", args=[99999]))           # doesn't exist
        self.assertEqual(hidden.status_code, missing.status_code)                     # both 404

        # The CSRF token in the logout form is re-randomised on every page
        # load by design, so blank it out; everything else must be identical.
        import re
        def without_token(response):
            return re.sub(rb'name="csrfmiddlewaretoken" value="[^"]+"', b"", response.content)
        self.assertEqual(without_token(hidden), without_token(missing))
