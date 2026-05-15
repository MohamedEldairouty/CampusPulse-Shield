"""Tiny raw-sqlite3 helper.

We deliberately use the stdlib `sqlite3` driver (no ORM) so that the SQL
strings are written explicitly. The vulnerable build interpolates user input
directly into these strings — that is the SQL Injection sink. The mitigated
build uses parameterized queries against the same helper.
"""
import sqlite3
from flask import g, current_app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app):
    app.teardown_appcontext(close_db)
