"""Mitigated app factory.

Three defenses wired in here:

 ① SameSite=Lax + Secret session  → blocks the *standalone* cross-site CSRF.
 ② Global CSRF token + before-request validator → blocks chained XSS-driven
    CSRF too, since the XSS payload can't read the token from the session.
 ③ Strict Content-Security-Policy header → defense-in-depth for XSS.

The SQLi fix and the output-encoding fix live in `routes.py` / templates,
not here — they're per-sink fixes, not app-wide config.
"""
import secrets
from flask import Flask, session, request, abort, g, render_template

from .db import init_app as init_db
from .auth import auth_bp
from .routes import main_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # ──────────────────────────────────────────────────────────────────────
    # 🛡️ Hardened configuration
    # ──────────────────────────────────────────────────────────────────────
    app.config.update(
        # In production this MUST come from an env var or secret manager.
        # For the demo we use a fixed key so sessions survive a restart.
        SECRET_KEY="hardened-build-secret-CHANGE-IN-PROD",

        # 🛡️ Session cookie hardening
        SESSION_COOKIE_HTTPONLY=True,       # no JS access to the cookie
        SESSION_COOKIE_SAMESITE="Lax",      # cross-site POSTs get NO cookie
        SESSION_COOKIE_SECURE=False,        # set True behind real HTTPS

        DATABASE_PATH="campuspulse.db",
    )

    init_db(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # ──────────────────────────────────────────────────────────────────────
    # 🛡️ CSRF token plumbing
    # ──────────────────────────────────────────────────────────────────────
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

    def get_csrf_token() -> str:
        """One token per session, regenerated on logout."""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    @app.before_request
    def csrf_protect():
        if request.method in SAFE_METHODS:
            return
        # Read submitted token from form OR header (so JSON clients can use it).
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, description="CSRF token missing or invalid.")

    @app.context_processor
    def inject_csrf():
        # Templates can call {{ csrf_token() }} to embed the hidden input.
        return {"csrf_token": get_csrf_token}

    # ──────────────────────────────────────────────────────────────────────
    # 🛡️ Defense-in-depth: Content-Security-Policy + other hardening headers
    # ──────────────────────────────────────────────────────────────────────
    @app.after_request
    def set_security_headers(resp):
        # 🛡️ Content-Security-Policy
        #
        #   script-src 'self'         → blocks inline <script> and remote JS.
        #                               THIS IS WHAT KILLS THE XSS PAYLOAD.
        #                               Must stay strict.
        #
        #   style-src 'self' 'unsafe-inline'
        #                             → allows inline style="..." attributes.
        #                               Pragmatic trade-off:
        #                                 • templates use inline style="..."
        #                                   for small layout tweaks (avatar
        #                                   colors, flex spacing, etc.)
        #                                 • CSS injection is far less dangerous
        #                                   than JS injection; the attacker
        #                                   can't exfiltrate cookies or fire
        #                                   POSTs from CSS alone.
        #                                 • Common industry posture.
        #
        #   font-src 'self' fonts.gstatic.com
        #   style-src ... fonts.googleapis.com
        #                             → allow Google Fonts (Inter + JetBrains
        #                               Mono) used by the UI.
        #
        #   img-src 'self' data: https:
        #                             → permit user-posted images and base64
        #                               favicons. Restrict to https remote.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        resp.headers["X-Frame-Options"]        = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"]        = "same-origin"
        return resp

    # Friendly 400 page (so the CSRF rejection is visible during the demo).
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html",
                               code=400,
                               title="Request blocked",
                               message=str(e.description) if hasattr(e, "description") else "Bad request"), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html",
                               code=403,
                               title="Forbidden",
                               message="You don't have permission to perform this action."), 403

    @app.context_processor
    def inject_build_info():
        return {"BUILD_FLAVOR": "mitigated", "BUILD_PORT": 5001}

    return app
