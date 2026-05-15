from flask import Flask
from .db import init_app as init_db
from .auth import auth_bp
from .routes import main_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # ──────────────────────────────────────────────────────────────────────
    # ⚠️  VULNERABLE configuration — intentionally weak for the demo.
    # ──────────────────────────────────────────────────────────────────────
    app.config.update(
        SECRET_KEY="vulnerable-build-secret-do-not-use-in-prod",
        # Session cookie is the auth carrier (so CSRF is possible at all).
        # No CSRF token in this build. We leave SameSite at Flask's default
        # so real browsers actually set the cookie over plain HTTP localhost.
        # The chained XSS-driven CSRF works regardless of SameSite because
        # the payload executes from the admin's own origin.
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=False,
        DATABASE_PATH="campuspulse.db",
    )

    init_db(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.context_processor
    def inject_build_info():
        return {"BUILD_FLAVOR": "vulnerable", "BUILD_PORT": 5000}

    return app
