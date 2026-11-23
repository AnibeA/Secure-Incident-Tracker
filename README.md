# Secure Incident Tracker

A web app where staff report security incidents and a security team investigates them. Access depends on each user's role, and the core security rules are enforced in the data model. Built with Python 3.14 and Django 6.1 for the Secure Web Development module (MSc Cyber Security, NCI).

## Features

- **Reporter** (default for new accounts): reports incidents and follows their own
- **Analyst**: sees all incidents; triages, investigates and resolves them
- **Admin**: everything an analyst does, plus managing users and roles

## Security improvements

| ID | Requirement | OWASP Top 10:2025 | Status |
| --- | --- | --- | --- |
| SR1 | **Authentication:** Argon2 password hashing, strong password policy, lockout after 5 failed logins | A07 | Not started (0%) |
| SR2 | **Authorisation:** least-privilege roles, per-incident access checks (IDOR), separation of duties, closed incidents locked | A01 | In progress (40%) |
| SR3 | **Sessions:** HttpOnly, SameSite and Secure cookies; 30-minute idle timeout; new session ID at login | A07 | Not started (0%) |
| SR4 | **Input and output:** form validation, ORM parameterised queries, template auto-escaping, CSRF tokens | A05 | In progress (20%) |
| SR5 | **Errors, logging, config:** DEBUG off, custom error pages, audit log, secrets in environment variables, supported versions only | A02, A03, A09, A10 | In progress (30%) |

Developed iteratively, with a security activity in every phase: requirements, threat modelling, secure implementation and testing.

## Project structure

```
accounts/          Custom User model with roles
incidents/         Incident and Comment models and the security rules
config/            Settings and URL routing
requirements.txt   Pinned package versions
.env.example       Settings the app needs (copy to .env)
```

## Setup

Requires Python 3.12+ (developed on 3.14).

```bash
git clone https://github.com/AnibeA/Secure-Incident-Tracker.git
cd Secure-Incident-Tracker
python3.14 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then set DJANGO_SECRET_KEY (see below)
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Generate a key with `python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"`, then open http://127.0.0.1:8000.

## Usage

_In progress._

## Testing

_In progress._

## References

[Django](https://www.djangoproject.com/) · [python-dotenv](https://pypi.org/project/python-dotenv/) · [OWASP Top 10:2025](https://owasp.org/Top10/2025/)