# Automated tests for sign-up and login. Run them with: python manage.py test
# Each test gets a fresh, empty test database, so tests can't affect each
# other or your real data. self.client is a fake browser that sends requests.

from django.test import TestCase     # base class for tests that use the database
from django.urls import reverse      # turns a URL name ("signup") into its address

from .models import User

# A password that passes the policy (12+ characters, not common), used below.
STRONG_PASSWORD = "Correct-Horse-Battery-42"


# Each method starting with "test_" is one test. The text in quotes under
# each name says what it proves; assert... lines fail the test if untrue.

class SignUpTests(TestCase):
    def test_new_user_is_a_reporter(self):
        """Least privilege: every new account starts with the lowest role."""
        self.client.post(reverse("signup"), {
            "username": "alice", "email": "alice@example.com",
            "password1": STRONG_PASSWORD, "password2": STRONG_PASSWORD,
        })
        self.assertEqual(User.objects.get(username="alice").role, User.Role.REPORTER)

    def test_cannot_make_yourself_admin_at_signup(self):
        """Mass assignment: an extra role field in the request is ignored."""
        self.client.post(reverse("signup"), {
            "username": "mallory", "email": "m@example.com",
            "password1": STRONG_PASSWORD, "password2": STRONG_PASSWORD,
            "role": "ADMIN",
        })
        self.assertEqual(User.objects.get(username="mallory").role, User.Role.REPORTER)

    def test_weak_password_is_rejected(self):
        """Password policy: short or common passwords don't create an account."""
        self.client.post(reverse("signup"), {
            "username": "bob", "email": "bob@example.com",
            "password1": "password1", "password2": "password1",
        })
        self.assertFalse(User.objects.filter(username="bob").exists())

    def test_password_is_stored_with_argon2(self):
        """Passwords are hashed with Argon2, never stored as plain text."""
        user = User.objects.create_user("carol", password=STRONG_PASSWORD)
        self.assertTrue(user.password.startswith("argon2"))


class LoginTests(TestCase):
    def test_home_requires_login(self):
        """Anonymous visitors are sent to the login page."""
        response = self.client.get(reverse("home"))
        self.assertRedirects(response, f"{reverse('login')}?next=/")

    def test_logout_rejects_get(self):
        """Logout only works as a POST, so a link on another site can't log you out."""
        user = User.objects.create_user("dave", password=STRONG_PASSWORD)
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse("logout")).status_code, 405)

    def test_superuser_gets_admin_role(self):
        """The first account made with createsuperuser can manage everyone else."""
        admin = User.objects.create_superuser("root", password=STRONG_PASSWORD)
        self.assertEqual(admin.role, User.Role.ADMIN)


class UserManagementTests(TestCase):
    """Only admins can change roles, and nobody can change their own."""

    def setUp(self):
        self.admin = User.objects.create_user("adele", password="x", role=User.Role.ADMIN)
        self.analyst = User.objects.create_user("ana", password="x", role=User.Role.ANALYST)
        self.reporter = User.objects.create_user("rob", password="x")

    def change_role(self, actor, target, role):
        # Helper: log in as `actor` and submit the role form for `target`.
        self.client.force_login(actor)
        return self.client.post(reverse("user_change_role", args=[target.pk]),
                                {f"user{target.pk}-role": role})

    def test_admin_can_promote_a_reporter(self):
        self.change_role(self.admin, self.reporter, "ANALYST")
        self.reporter.refresh_from_db()
        self.assertEqual(self.reporter.role, User.Role.ANALYST)

    def test_analyst_cannot_manage_users(self):
        """Role check: analysts get 403, on the list and on changing roles."""
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(reverse("user_list")).status_code, 403)
        self.assertEqual(self.change_role(self.analyst, self.reporter, "ADMIN").status_code, 403)
        self.reporter.refresh_from_db()
        self.assertEqual(self.reporter.role, User.Role.REPORTER)

    def test_reporter_cannot_promote_themselves(self):
        """Elevation of privilege: a reporter can't make themselves an admin."""
        response = self.change_role(self.reporter, self.reporter, "ADMIN")
        self.assertEqual(response.status_code, 403)
        self.reporter.refresh_from_db()
        self.assertEqual(self.reporter.role, User.Role.REPORTER)

    def test_admin_cannot_change_own_role(self):
        """Stops an admin locking themselves (and everyone) out of user management."""
        self.assertEqual(self.change_role(self.admin, self.admin, "REPORTER").status_code, 403)

    def test_invalid_role_is_rejected(self):
        """Input validation: only the three real roles are accepted."""
        self.change_role(self.admin, self.reporter, "SUPERADMIN")
        self.reporter.refresh_from_db()
        self.assertEqual(self.reporter.role, User.Role.REPORTER)
