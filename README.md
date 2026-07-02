# 🔐 Secure Authentication System

A complete login/registration system with bcrypt password hashing and JWT token-based authentication — entirely local, no third-party auth service or API key needed.

## Tech Stack
- **Backend**: Python + Flask
- **Password Hashing**: bcrypt (via flask-bcrypt)
- **Tokens**: PyJWT (access + refresh tokens)
- **Database**: SQLite (users, login history)
- **Frontend**: Vanilla JS dark dashboard

## Why no API key is needed
bcrypt hashing and JWT signing/verification are pure cryptographic algorithms that run as Python code on your own machine. There's no external auth provider (like Auth0 or Firebase) involved — your backend IS the auth server.

## Features
- **Registration** with live password strength meter (score 0–100)
- **Password requirements**: 8+ chars, upper, lower, number, special character
- **bcrypt hashing** — passwords never stored in plain text
- **JWT access tokens** (30 min expiry) + refresh tokens (7 days)
- **Account lockout** after 5 failed login attempts (15 min lockout)
- **Login history log** — tracks every attempt, success or fail
- **Protected routes** using `@token_required` decorator
- **Dashboard** showing account info + decoded JWT

## Setup

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

## Security Notes for Production
This is built for a college project / demo. For real production use, you'd also want to:
- Set `SECRET_KEY` via environment variable (already supported, just hardcoded a dev default)
- Use HTTPS only
- Add rate limiting (Flask-Limiter)
- Implement token blocklist for true logout invalidation
- Add email verification
- Use `httpOnly` cookies instead of localStorage for refresh tokens (XSS protection)

## API Endpoints
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|--------------|
| POST | /api/register | No | Create new account |
| POST | /api/login | No | Login, returns JWT |
| POST | /api/refresh | No | Get new access token |
| GET | /api/me | Yes | Get current user info |
| GET | /api/login_history | Yes | Last 10 login attempts |
| POST | /api/check_password_strength | No | Live strength check |
| POST | /api/logout | Yes | Logout (client discards token) |

## Project Structure
```
secure_auth/
├── app.py              # Flask app: bcrypt + JWT + SQLite
├── auth.db             # SQLite DB (auto-created)
├── requirements.txt
└── templates/
    └── index.html       # Login/Register/Dashboard UI
```
