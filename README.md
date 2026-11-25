# Secure Incident Tracker

## Project Title and Overview

A web application where staff report security incidents (phishing, malware, lost devices, data leaks) and a security team triages, investigates and resolves them. Every user can only see and do what their role allows, and the core security rules are enforced in the data model, so no page can bypass them.

Built with Python 3.14 and Django 6.1 for the Secure Web Development module, MSc in Cyber Security, National College of Ireland.

## Features and Security Objectives

**Features**
- Sign up, log in and log out
- Report an incident (title, category, severity, description)
- Reporters see and follow their own incidents; analysts and admins see all of them
- Incident workflow: Open → Triaged → Investigating → Resolved → Closed
- Assign incidents to analysts
- Comment on incidents
- Admins manage user roles and read the audit log

**Roles**
- **Reporter** (default for every new account): reports incidents and follows their own
- **Analyst:** sees all incidents; triages, investigates and resolves them
- **Admin:** everything an analyst does, plus managing users and reading the audit log

**Security objectives:** stop users reaching data or actions outside their role, protect accounts and sessions, block injection attacks, and keep a trustworthy audit trail. Each objective maps to a requirement in [Security Improvements](#security-improvements).

## Project Structure

```
accounts/          Custom User model with roles, sign-up, role-check decorators, user management
incidents/         Incident and Comment models (the security rules live here), workflow views, forms
audit/             Append-only audit log: model, record() helper, login/lockout signal handlers
config/            settings.py (all hardening, every line commented) and the main URL list
templates/         HTML pages, including custom 400/403/404/500 error pages
static/css/        The stylesheet (served from our own site, as the Content Security Policy requires)
docs/security/     Bandit and Semgrep reports
requirements.txt   Pinned versions of the packages the app needs
requirements-dev.txt  Security scanning tools (Bandit, Semgrep)
.env.example       The settings the app needs (copy to .env)
```

## Setup and Installation

Requires Python 3.12 or newer (developed on 3.14).

```bash
git clone https://github.com/AnibeA/Secure-Incident-Tracker.git
cd Secure-Incident-Tracker
python3.14 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Generate a secret key and paste it into `.env` as `DJANGO_SECRET_KEY`:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Then create the database and the first admin account, and start the server:

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open http://127.0.0.1:8000. On a real server, set `DJANGO_DEBUG=False`, `DJANGO_ALLOWED_HOSTS` to your domain, and `DJANGO_HTTPS=True` once HTTPS is set up.

## Usage Guidelines

1. **Sign up** at `/accounts/signup/`. New accounts are Reporters. Passwords need 12+ characters and can't be common.
2. **Report an incident** with the button on the home page. You'll see only your own incidents in the list.
3. **Admins** (the account made with `createsuperuser`) open **Users** in the top bar to promote someone to Analyst or Admin. Nobody can change their own role.
4. **Analysts** open any incident to move it through the workflow and assign it. You can't resolve or close an incident you reported yourself; another analyst has to (separation of duties).
5. **Closed incidents are locked:** no edits, status changes, reassignments or comments.
6. **Admins** open **Audit log** to see logins, failed logins, lockouts, denied access and every change.
7. Five wrong passwords lock an account for 15 minutes. To unlock early: `python manage.py axes_reset`.

## Security Improvements

| ID | Requirement | How it's implemented | OWASP Top 10:2025 | Status |
| --- | --- | --- | --- | --- |
| SR1 | Authentication | Argon2 password hashing; 12-character password policy; lockout after 5 failed logins (by account and by IP) with django-axes | A07 | Complete (100%) |
| SR2 | Authorisation | Least-privilege roles; role-check decorators on every restricted view; one per-incident access check (IDOR returns 404 and is logged); separation of duties; closed-incident lock; nobody changes their own role | A01 | Complete (100%) |
| SR3 | Session management | HttpOnly and SameSite cookies (Secure on HTTPS); 30-minute idle timeout; new session ID at login; POST-only logout | A07 | Complete (100%) |
| SR4 | Input validation and output encoding | Forms with explicit fields and fixed choices (blocks mass assignment); ORM-only queries; template auto-escaping; CSRF tokens; strict Content Security Policy | A05 | Complete (100%) |
| SR5 | Error handling, logging and configuration | DEBUG off by default; custom error pages; append-only audit log; secrets in `.env`; security headers; supported versions of Python and Django only | A02, A03, A09, A10 | Complete (100%) |

## Testing Process

**Functional security tests:** 62 automated tests, run with:

```bash
python manage.py test
```

They cover the three major security features: authentication and sessions, access control (IDOR, role checks, separation of duties, the closed lock, mass assignment), and input handling (XSS, SQL injection, CSRF, invalid values), plus the audit log. Every misuse case from the threat model is covered by at least one test.

**Static analysis (SAST):**

```bash
pip install -r requirements-dev.txt
bandit -r accounts incidents audit config
semgrep scan --config p/django --config p/python --metrics=off --exclude .venv
```

| Tool | Result |
| --- | --- |
| Bandit 1.9 | 0 Medium, 0 High. 14 Low, all dummy passwords in test files (false positives) |
| Semgrep 1.182.1 (152 Django and Python rules) | 0 findings |

Full reports are in `docs/security/`. Semgrep 1.182 is pinned because later versions don't support Intel Macs.

## Contributions and References

**My contributions:** the application design and threat model; the role model and all access-control rules (`incidents/models.py`, `accounts/decorators.py`, `get_incident_for()`); the incident workflow with separation of duties; the append-only audit log (`audit/`); the hardened configuration (`config/settings.py`); and the 62 security tests.

**Frameworks and libraries used:**
- [Django](https://www.djangoproject.com/): the web framework
- [django-axes](https://github.com/jazzband/django-axes): login lockout
- [argon2-cffi](https://github.com/hynek/argon2-cffi): Argon2 password hashing
- [python-dotenv](https://github.com/theskumar/python-dotenv): loading settings from `.env`
- [Bandit](https://github.com/PyCQA/bandit) and [Semgrep](https://semgrep.dev/): static analysis
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/): mapping the security requirements
