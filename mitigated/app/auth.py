"""Auth: register / login / logout.

Auth itself is NOT one of the three demo vulnerabilities, so it uses
parameterized queries even in the vulnerable build — we don't want a
random SQLi here distracting from the *intentional* one in /search.
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username  = (request.form.get("username")  or "").strip()
        email     = (request.form.get("email")     or "").strip()
        full_name = (request.form.get("full_name") or "").strip()
        password  =  request.form.get("password")  or ""
        major     = (request.form.get("major")     or "").strip()
        year      = (request.form.get("year")      or "").strip()

        if not (username and email and full_name and password):
            flash("All required fields must be filled in.", "error")
            return render_template("register.html")

        db = get_db()
        exists = db.execute(
            "SELECT 1 FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if exists:
            flash("Username or email already taken.", "error")
            return render_template("register.html")

        db.execute(
            "INSERT INTO users(username,email,password_hash,role,full_name,bio,major,year) "
            "VALUES (?,?,?,'student',?,'',?,?)",
            (username, email, generate_password_hash(password), full_name, major, year),
        )
        db.commit()
        flash("Account created — you can log in now.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password =  request.form.get("password") or ""

        row = get_db().execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not row or not check_password_hash(row["password_hash"], password):
            flash("Invalid credentials.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"]  = row["id"]
        session["username"] = row["username"]
        session["role"]     = row["role"]
        return redirect(url_for("main.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    # POST-only logout so it can't be triggered via <a> / <img> tags.
    # Global CSRF middleware enforces the token check.
    session.clear()
    return redirect(url_for("auth.login"))
