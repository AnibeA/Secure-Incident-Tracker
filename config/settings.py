"""
Settings for the Secure Incident Tracker.

Every setting that matters for security has a comment saying why, and which
security requirement (SR1 to SR5) it supports. Values that differ between your
laptop and a real server (the secret key, DEBUG, HTTPS) come from the .env
file, so the code itself never changes between the two.
"""

import os                       # reads environment variables
from datetime import timedelta  # used for the lockout time below
from pathlib import Path        # builds file paths that work on any operating system

from django.utils.csp import CSP   # named values for the Content Security Policy below
from dotenv import load_dotenv     # loads the .env file into environment variables

# BASE_DIR is the project folder (the one containing manage.py).
BASE_DIR = Path(__file__).resolve().parent.parent

# Read the .env file (secret key, DEBUG, HTTPS flag). It's kept out of Git.
load_dotenv(BASE_DIR / ".env")


# ---- Secrets and debug mode (SR5) ------------------------------------------

# The key Django uses to sign sessions and password-reset links. Read from
# .env; os.environ[...] crashes if it's missing, so the app never starts with
# a weak or default key (fail securely).
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# Debug pages show code, settings and every URL to whoever triggers an error.
# Off unless .env explicitly says DJANGO_DEBUG=True (secure default).
DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"

# Which web addresses this app answers to. Requests for any other host are
# refused, which blocks Host-header attacks. Set in .env on a real server.
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

# True only on a real server that has an HTTPS certificate. On your laptop the
# dev server only speaks plain HTTP, so these HTTPS-only settings stay off there.
USE_HTTPS = os.environ.get("DJANGO_HTTPS", "False") == "True"


# ---- Apps --------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",          # Django's admin site (/admin/)
    "django.contrib.auth",           # users, passwords, login
    "django.contrib.contenttypes",
    "django.contrib.sessions",       # remembers who is logged in
    "django.contrib.messages",       # one-off messages ("Incident reported")
    "django.contrib.staticfiles",    # serves our CSS
    "axes",                          # login lockout after repeated failures (SR1)
    "accounts",                      # our users, roles, sign-up, user management
    "incidents",                     # our incidents, workflow, comments
]

# Middleware runs on every request, in this order, before any view.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",        # HTTPS redirect, HSTS and other security headers
    "django.contrib.sessions.middleware.SessionMiddleware",  # loads the session
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",             # checks the CSRF token on every form submission (SR4)
    "django.contrib.auth.middleware.AuthenticationMiddleware",  # works out who the user is
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",   # stops other sites showing ours in a frame
    "django.middleware.csp.ContentSecurityPolicyMiddleware",    # sends the Content Security Policy below (SR5)
    "axes.middleware.AxesMiddleware",                           # blocks locked-out logins; must be last
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],   # our project-wide templates folder
        "APP_DIRS": True,
        "OPTIONS": {
            # Templates auto-escape every {{ value }} by default (blocks XSS, SR4).
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# ---- Database ----------------------------------------------------------------

# SQLite: a single file (db.sqlite3), kept out of Git by .gitignore.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# ---- Users and passwords (SR1) -------------------------------------------------

# Use our own User model (the one with roles) instead of Django's default.
AUTH_USER_MODEL = "accounts.User"

# How a login is checked. Axes goes first so a locked-out account is refused
# before the password is even looked at; then Django's normal check.
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# The password policy, checked at sign-up.
AUTH_PASSWORD_VALIDATORS = [
    # Not too similar to the username or email.
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    # At least 12 characters (Django's default is 8).
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    # Not on a list of 20,000 common passwords.
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    # Not entirely numbers.
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Argon2 first: every new password is hashed with it. PBKDF2 stays as a
# fallback so older hashes can still be checked (upgraded at next login).
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

LOGIN_URL = "login"            # where @login_required sends users who aren't logged in
LOGIN_REDIRECT_URL = "home"    # where users land after logging in
LOGOUT_REDIRECT_URL = "login"  # where users land after logging out


# ---- Login lockout with django-axes (SR1, misuse case MC4) --------------------

AXES_FAILURE_LIMIT = 5                        # 5 wrong passwords in a row...
AXES_COOLOFF_TIME = timedelta(minutes=15)     # ...locks the account for 15 minutes
# Two separate locks: 5 failures on one ACCOUNT locks that account (stops
# guessing one person's password), and 5 failures from one IP ADDRESS locks
# that address (stops "password spraying": one common password tried against
# many accounts). Trade-off: an attacker could deliberately lock someone's
# account for 15 minutes; accepted, as it's short and nothing is exposed.
AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]
AXES_RESET_ON_SUCCESS = True                  # a correct login resets the count
AXES_LOCKOUT_TEMPLATE = "registration/locked.html"   # the page shown when locked out


# ---- Sessions and cookies (SR3) ----------------------------------------------------

SESSION_COOKIE_HTTPONLY = True    # JavaScript can't read the session cookie, so XSS can't steal it
SESSION_COOKIE_SAMESITE = "Lax"   # the browser won't send it with most requests started by other sites (CSRF defence)
SESSION_COOKIE_AGE = 30 * 60      # sessions last 30 minutes...
SESSION_SAVE_EVERY_REQUEST = True # ...counted from the last click, so it's an idle timeout
SESSION_EXPIRE_AT_BROWSER_CLOSE = True   # closing the browser ends the session

# Cookies only travel over HTTPS on a real server (off on your laptop, which is HTTP).
SESSION_COOKIE_SECURE = USE_HTTPS
CSRF_COOKIE_SECURE = USE_HTTPS


# ---- Security headers (SR5) --------------------------------------------------------

SECURE_CONTENT_TYPE_NOSNIFF = True       # browsers must trust our file types, not guess them
X_FRAME_OPTIONS = "DENY"                 # no site may show ours inside a frame (blocks clickjacking)
SECURE_REFERRER_POLICY = "same-origin"   # our addresses aren't leaked to other sites when users click links

# HTTPS-only behaviour, switched on for a real server with DJANGO_HTTPS=True.
SECURE_SSL_REDIRECT = USE_HTTPS                         # send http:// visitors to https://
SECURE_HSTS_SECONDS = 31536000 if USE_HTTPS else 0      # tell browsers "always use HTTPS here" for a year
SECURE_HSTS_INCLUDE_SUBDOMAINS = USE_HTTPS

# Content Security Policy: the browser may only load scripts, styles and images
# from our own site. Even if an attacker got HTML into a page, the browser
# would refuse to run their script or load it from elsewhere (defence in depth
# on top of template escaping).
SECURE_CSP = {
    "default-src": [CSP.SELF],     # anything not listed below: only from our own site
    "script-src": [CSP.SELF],      # no inline scripts, no scripts from other sites
    "style-src": [CSP.SELF],       # only our own stylesheet
    "img-src": [CSP.SELF, "data:"],
    "object-src": [CSP.NONE],      # no Flash or other plug-ins
    "base-uri": [CSP.SELF],
    "form-action": [CSP.SELF],     # forms may only submit to our own site
    "frame-ancestors": [CSP.NONE], # same as X_FRAME_OPTIONS, for modern browsers
}


# ---- Language, time and static files ---------------------------------------------

LANGUAGE_CODE = "en-ie"
TIME_ZONE = "Europe/Dublin"
USE_I18N = True
USE_TZ = True   # store times in UTC, show them in Dublin time

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]   # our CSS lives here

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
