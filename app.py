import os
import re
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "application-security-demo-secret")

USERS = {
    "admin": {
        "password": "Admin@123",
        "role": "admin",
        "display_name": "Security Admin",
    },
    "Charan": {
        "password": "I@am#here",
        "role": "user",
        "display_name": "Charan",
    },
}

NOTES = {
    "admin": ["Review security controls"],
    "Charan": ["Application Security Lab"],
}

EVENTS = [
    {"time": "SYSTEM", "type": "SYSTEM", "message": "Security controls initialized", "level": "success"},
    {"time": "SYSTEM", "type": "HEADERS", "message": "CSP and browser security headers enabled", "level": "success"},
    {"time": "SYSTEM", "type": "RBAC", "message": "Role-based authorization enabled", "level": "success"},
]

CONTROLS = [
    ("Authentication", "Credential validation and generic login errors.", "AUTH"),
    ("Role-based access", "Protected routes verify the user's role.", "RBAC"),
    ("Input validation", "Suspicious and malformed input is rejected.", "INPUT"),
    ("Security headers", "CSP and defensive HTTP headers are enabled.", "HTTP"),
    ("Session security", "Authenticated state is cleared on logout.", "SESSION"),
    ("Error handling", "Dedicated 404 and 500 responses are provided.", "ERROR"),
]


def get_user():
    return USERS.get(session.get("username"))


def validate_username(username):
    return bool(username and re.fullmatch(r"[A-Za-z0-9_]{3,30}", username))


def validate_note(note):
    if not note or len(note) > 500:
        return False

    blocked = ("<script", "javascript:", "union select", "';--")
    value = note.lower()
    return not any(item in value for item in blocked)


def add_event(event_type, message, level="info"):
    EVENTS.insert(0, {
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": event_type,
        "message": message,
        "level": level,
    })
    del EVENTS[12:]


def require_role(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = get_user()
            if not user or user["role"] != role:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/")
def home():
    username = session.get("username")
    return render_template(
        "index.html",
        page="dashboard",
        user=get_user(),
        notes=NOTES.get(username, []) if username else [],
        events=EVENTS[:6],
        controls=CONTROLS,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_username(username):
            error = "Enter a valid username."
            add_event("AUTH", "Malformed username rejected", "warning")
        elif username not in USERS or USERS[username]["password"] != password:
            error = "Invalid username or password."
            add_event("AUTH", "Failed authentication attempt", "danger")
        else:
            session.clear()
            session["username"] = username
            add_event("AUTH", f"Successful login: {username}", "success")
            return redirect(url_for("home"))

    return render_template("index.html", page="login", user=get_user(), error=error)


@app.route("/logout")
def logout():
    username = session.get("username")
    if username:
        add_event("AUTH", f"Logout: {username}", "info")
    session.clear()
    return redirect(url_for("home"))


@app.route("/notes", methods=["POST"])
def add_note():
    if not get_user():
        return redirect(url_for("login"))

    note = request.form.get("note", "").strip()

    if not validate_note(note):
        add_event("INPUT", "Suspicious note input blocked", "warning")
        return redirect(url_for("home") + "#lab")

    NOTES.setdefault(session["username"], []).append(note)
    add_event("INPUT", "Validated note accepted", "success")
    return redirect(url_for("home") + "#lab")


@app.route("/admin")
@require_role("admin")
def admin():
    safe_users = {
        name: {"role": data["role"], "display_name": data["display_name"]}
        for name, data in USERS.items()
    }
    return jsonify({"users": safe_users, "security_events": EVENTS})


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(404)
def not_found(_error):
    return render_template(
        "index.html",
        page="error",
        error_code=404,
        error_message="The page you requested does not exist.",
    ), 404


@app.errorhandler(500)
def server_error(_error):
    return render_template(
        "index.html",
        page="error",
        error_code=500,
        error_message="The application encountered an internal error.",
    ), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5002)), debug=False)
