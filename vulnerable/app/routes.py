"""Main routes for the VULNERABLE build.

This file owns:
  • Dashboard / profile / search / course detail (student-facing pages)
  • Admin & TA management endpoints (users, courses, professors, enrollments)

Three intentional security flaws are clearly marked with ⚠️ banners:

  VULN #1  — SQL Injection           → GET /search          (raw SQL concat)
  VULN #2  — Reflected XSS           → search results page  (echo via |safe)
  VULN #3  — CSRF + Mass-Assignment  → POST /admin/users/set-role
             (no CSRF token, no role whitelist — attacker can set role=admin)
"""
from functools import wraps
from flask import (
    Blueprint, render_template, request, redirect, url_for, session, flash, abort
)
from werkzeug.security import generate_password_hash
from .db import get_db

main_bp = Blueprint("main", __name__)


# ────────────────────────── auth gates ──────────────────────────

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("auth.login"))
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return deco


# ────────────────────────── helpers ─────────────────────────────

def _current_user():
    return get_db().execute(
        "SELECT id, username, email, role, full_name, bio, major, year FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()


def _course_profs(course_id):
    return get_db().execute(
        "SELECT p.id, p.name FROM professors p "
        "JOIN course_professors cp ON cp.professor_id = p.id "
        "WHERE cp.course_id = ? ORDER BY p.name",
        (course_id,),
    ).fetchall()


def _user_courses(user_id):
    rows = get_db().execute(
        "SELECT c.id, c.code, c.title, c.credits, e.grade, e.professor_id, "
        "       p.name AS prof_name "
        "FROM courses c "
        "JOIN enrollments e ON e.course_id = c.id "
        "LEFT JOIN professors p ON p.id = e.professor_id "
        "WHERE e.user_id = ? ORDER BY c.code",
        (user_id,),
    ).fetchall()
    return [{
        "id": r["id"], "code": r["code"], "title": r["title"],
        "credits": r["credits"],
        "profs": _course_profs(r["id"]),         # all lecturers on the course
        "my_prof": r["prof_name"],               # the specific lecturer this student is with
        "grade": r["grade"],                     # None = ungraded
    } for r in rows]


# ────────────────────────── grades + GPA ────────────────────────
#
# 4.0 scale. A+ caps at 4.0 (same as A) — that's the standard US convention.
GRADE_POINTS = {
    "A+": 4.0, "A": 4.0, "A-": 3.7,
    "B+": 3.3, "B": 3.0, "B-": 2.7,
    "C+": 2.3, "C": 2.0, "C-": 1.7,
    "D+": 1.3, "D": 1.0,
    "F":  0.0,
}
# Allowed letter grades plus the empty string (= clear / mark ungraded).
ALLOWED_GRADES = {""} | set(GRADE_POINTS.keys())

# Stable display order — used in grade dropdowns.
GRADE_OPTIONS = ["", "A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "F"]


def _student_gpa(user_id):
    """Live-compute a student's GPA on the 4.0 scale, weighted by credit hours.
    Returns a float rounded to 2 decimals, or None if no graded courses yet."""
    rows = get_db().execute(
        "SELECT e.grade, c.credits "
        "FROM enrollments e JOIN courses c ON c.id = e.course_id "
        "WHERE e.user_id = ? AND e.grade IS NOT NULL AND e.grade != ''",
        (user_id,),
    ).fetchall()
    total_pts = 0.0
    total_cr  = 0
    for r in rows:
        pts = GRADE_POINTS.get(r["grade"])
        if pts is None:
            continue
        total_pts += pts * r["credits"]
        total_cr  += r["credits"]
    if total_cr == 0:
        return None
    return round(total_pts / total_cr, 2)


def _display_gpa(user_row):
    """Return the GPA to show for a user row.
       Students → live-computed from grades. TAs/admin → stored `users.gpa`."""
    if user_row["role"] == "student":
        return _student_gpa(user_row["id"])
    # sqlite Row supports indexing; fall back to None if column absent.
    try:
        return user_row["gpa"]
    except (KeyError, IndexError):
        return None


def _is_enrolled(user_id, course_id):
    return get_db().execute(
        "SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?",
        (user_id, course_id),
    ).fetchone() is not None


def _course_stats(course_id):
    db = get_db()
    n_enrolled = db.execute(
        "SELECT COUNT(*) FROM enrollments WHERE course_id = ?", (course_id,)
    ).fetchone()[0]
    n_profs = db.execute(
        "SELECT COUNT(*) FROM course_professors WHERE course_id = ?", (course_id,)
    ).fetchone()[0]
    return n_enrolled, n_profs


def _get_or_create_prof(name):
    """Return professor id for `name`, inserting if it doesn't exist."""
    name = (name or "").strip()
    if not name:
        return None
    db = get_db()
    row = db.execute("SELECT id FROM professors WHERE name = ?", (name,)).fetchone()
    if row:
        return row["id"]
    cur = db.execute("INSERT INTO professors(name) VALUES (?)", (name,))
    return cur.lastrowid


def _replace_course_profs(course_id, prof_names):
    db = get_db()
    db.execute("DELETE FROM course_professors WHERE course_id = ?", (course_id,))
    seen = set()
    for name in prof_names:
        name = (name or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        pid = _get_or_create_prof(name)
        if pid:
            db.execute(
                "INSERT OR IGNORE INTO course_professors(course_id, professor_id) VALUES (?, ?)",
                (course_id, pid),
            )


# ────────────────────────── root / dashboard ────────────────────

@main_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    me = _current_user()
    stats = {}

    if me["role"] == "student":
        my_courses = _user_courses(me["id"])
    else:
        my_courses = []
        stats["students"]    = db.execute("SELECT COUNT(*) FROM users WHERE role = 'student'").fetchone()[0]
        stats["tas"]         = db.execute("SELECT COUNT(*) FROM users WHERE role = 'ta'").fetchone()[0]
        stats["courses"]     = db.execute("SELECT COUNT(*) FROM courses").fetchone()[0]
        stats["professors"]  = db.execute("SELECT COUNT(*) FROM professors").fetchone()[0]
        stats["enrollments"] = db.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0]

    return render_template("dashboard.html", me=me, my_courses=my_courses, stats=stats)


# ────────────────────────── profile (editable) ──────────────────

@main_bp.route("/profile", methods=["GET", "POST"])
@login_required
def my_profile():
    db = get_db()
    me = _current_user()

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        email     = (request.form.get("email")     or "").strip()
        bio       = (request.form.get("bio")       or "").strip()
        major     = (request.form.get("major")     or "").strip()
        new_pwd   =  request.form.get("new_password") or ""

        # Year is only editable for students; non-students are locked to 'Faculty'.
        if me["role"] == "student":
            year = (request.form.get("year") or "").strip()
        else:
            year = "Faculty"

        if not (full_name and email):
            flash("Full name and email are required.", "error")
            return redirect(url_for("main.my_profile"))

        clash = db.execute(
            "SELECT 1 FROM users WHERE email = ? AND id != ?",
            (email, me["id"]),
        ).fetchone()
        if clash:
            flash("That email is already taken.", "error")
            return redirect(url_for("main.my_profile"))

        if new_pwd:
            db.execute(
                "UPDATE users SET full_name=?, email=?, bio=?, major=?, year=?, password_hash=? WHERE id=?",
                (full_name, email, bio, major, year, generate_password_hash(new_pwd), me["id"]),
            )
        else:
            db.execute(
                "UPDATE users SET full_name=?, email=?, bio=?, major=?, year=? WHERE id=?",
                (full_name, email, bio, major, year, me["id"]),
            )
        db.commit()
        flash("Profile saved ✔", "success")
        return redirect(url_for("main.my_profile"))

    my_courses = _user_courses(me["id"]) if me["role"] == "student" else []
    return render_template("profile_edit.html", me=me, my_courses=my_courses)


@main_bp.route("/profile/<int:user_id>")
@login_required
def view_profile(user_id):
    user = get_db().execute(
        "SELECT id, username, email, role, full_name, bio, major, year FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not user:
        abort(404)
    courses = _user_courses(user_id) if user["role"] == "student" else []
    return render_template("profile_view.html", profile_user=user, courses=courses)


# ─────────────────────────────────────────────────────────────────────────
# ⚠️  VULN #1 — SQL INJECTION   /search?q=...
# ⚠️  VULN #2 — REFLECTED XSS   q rendered with |safe on the template
# ─────────────────────────────────────────────────────────────────────────
@main_bp.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    rows = []
    sql_used = None
    error = None
    me = _current_user()

    if q:
        # ❌ String interpolation directly into SQL — DO NOT do this in real code.
        # The subquery flattens all professors of a course into one comma-joined
        # 'instructor' column so the visible shape stays at 5 cols and the
        # classic UNION SELECT payload (5 cols from users) still demonstrates.
        sql_used = (
            "SELECT c.id, c.code, c.title, "
            "(SELECT GROUP_CONCAT(p.name, ', ') FROM professors p "
            " JOIN course_professors cp ON cp.professor_id = p.id "
            " WHERE cp.course_id = c.id) AS instructor, "
            "c.credits "
            "FROM courses c "
            f"WHERE c.code LIKE '%{q}%' OR c.title LIKE '%{q}%'"
        )
        try:
            rows = get_db().execute(sql_used).fetchall()
        except Exception as e:
            error = str(e)

    # Build a set of legitimate (course_id, course_code) pairs so we can tell
    # genuine course results apart from UNION-injected rows. Real courses
    # render normally; injected rows additionally reveal their numeric id —
    # which is the recon detail an attacker needs to craft Stage-3 payloads.
    real_course_keys = {
        (c["id"], c["code"])
        for c in get_db().execute("SELECT id, code FROM courses").fetchall()
    }

    enriched = []
    for r in rows:
        try:
            cid = int(r["id"]) if r["id"] is not None else None
        except (KeyError, IndexError, ValueError, TypeError):
            cid = None
        try:
            rcode = r["code"]
        except (KeyError, IndexError, TypeError):
            rcode = None
        enrolled = _is_enrolled(me["id"], cid) if cid else False
        is_real_course = (cid, rcode) in real_course_keys
        enriched.append({"row": r, "enrolled": enrolled,
                         "is_real_course": is_real_course})

    return render_template(
        "search.html",
        q=q, results=enriched, sql_used=sql_used, error=error, me=me,
    )


# ────────────────────────── course catalog & detail ─────────────

@main_bp.route("/courses")
@login_required
def courses_catalog():
    db = get_db()
    me = _current_user()
    base = db.execute(
        "SELECT id, code, title, credits FROM courses ORDER BY code"
    ).fetchall()
    courses = []
    for c in base:
        n_enrolled, n_profs = _course_stats(c["id"])
        courses.append({
            "id": c["id"], "code": c["code"], "title": c["title"], "credits": c["credits"],
            "profs": _course_profs(c["id"]),
            "enrolled_count": n_enrolled, "prof_count": n_profs,
        })
    my_ids = {c["id"] for c in _user_courses(me["id"])} if me["role"] == "student" else set()
    return render_template("courses.html", courses=courses, my_ids=my_ids, me=me)


@main_bp.route("/courses/<int:course_id>")
@login_required
def course_detail(course_id):
    db = get_db()
    me = _current_user()
    course = db.execute(
        "SELECT id, code, title, description, credits FROM courses WHERE id = ?",
        (course_id,),
    ).fetchone()
    if not course:
        abort(404)

    profs = _course_profs(course_id)

    # Each enrolled student carries their assigned lecturer + grade.
    enrolled_students = db.execute(
        "SELECT u.id, u.username, u.full_name, u.email, "
        "       e.professor_id, p.name AS prof_name, e.grade "
        "FROM users u "
        "JOIN enrollments e ON e.user_id = u.id "
        "LEFT JOIN professors p ON p.id = e.professor_id "
        "WHERE e.course_id = ? AND u.role = 'student' "
        "ORDER BY u.full_name",
        (course_id,),
    ).fetchall()
    enrolled_ids = {s["id"] for s in enrolled_students}

    other_students = []
    if me["role"] in ("ta", "admin"):
        all_students = db.execute(
            "SELECT id, username, full_name FROM users WHERE role = 'student' ORDER BY full_name"
        ).fetchall()
        other_students = [s for s in all_students if s["id"] not in enrolled_ids]

    am_i_enrolled = me["id"] in enrolled_ids
    my_enrollment = None
    if am_i_enrolled:
        my_enrollment = next(s for s in enrolled_students if s["id"] == me["id"])

    return render_template(
        "course_detail.html",
        course=course, profs=profs,
        enrolled_students=enrolled_students,
        other_students=other_students,
        am_i_enrolled=am_i_enrolled,
        my_enrollment=my_enrollment,
        grade_options=GRADE_OPTIONS,
        me=me,
    )


# ─── enrollment management (TA + admin) ───────────────────────────

@main_bp.route("/courses/<int:course_id>/enroll", methods=["POST"])
@role_required("ta", "admin")
def enroll_student(course_id):
    try:
        student_id = int(request.form.get("student_id", "0"))
    except ValueError:
        student_id = 0
    if student_id <= 0:
        flash("Invalid student.", "error")
        return redirect(url_for("main.course_detail", course_id=course_id))

    # Resolve the lecturer:
    #   • If the course has 1 prof  → auto-assign that prof.
    #   • If the course has 2+ profs → require `professor_id` from the form,
    #     and check it actually teaches this course.
    profs = _course_profs(course_id)
    prof_id = None
    if len(profs) == 1:
        prof_id = profs[0]["id"]
    elif len(profs) > 1:
        try:
            chosen = int(request.form.get("professor_id", "0"))
        except ValueError:
            chosen = 0
        valid = {p["id"] for p in profs}
        if chosen not in valid:
            flash("Please pick a lecturer for this co-taught course.", "error")
            return redirect(url_for("main.course_detail", course_id=course_id))
        prof_id = chosen
    # If course has 0 profs we still allow enrollment with NULL lecturer.

    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO enrollments(user_id, course_id, professor_id, grade) "
        "VALUES (?, ?, ?, NULL)",
        (student_id, course_id, prof_id),
    )
    db.commit()
    flash("Student enrolled.", "success")
    return redirect(url_for("main.course_detail", course_id=course_id))


@main_bp.route("/courses/<int:course_id>/withdraw", methods=["POST"])
@role_required("ta", "admin")
def withdraw_student(course_id):
    try:
        student_id = int(request.form.get("student_id", "0"))
    except ValueError:
        student_id = 0
    if student_id <= 0:
        flash("Invalid student.", "error")
        return redirect(url_for("main.course_detail", course_id=course_id))

    db = get_db()
    # Policy: TAs cannot withdraw an already-graded student. Only the admin
    # has the authority — and only after clearing/lowering the grade if needed.
    row = db.execute(
        "SELECT grade FROM enrollments WHERE user_id = ? AND course_id = ?",
        (student_id, course_id),
    ).fetchone()
    if not row:
        flash("Enrollment not found.", "error")
        return redirect(url_for("main.course_detail", course_id=course_id))
    is_graded = row["grade"] is not None and row["grade"] != ""
    if is_graded and session["role"] == "ta":
        flash("This enrollment is already graded — only an admin can withdraw it.", "error")
        return redirect(url_for("main.course_detail", course_id=course_id))

    db.execute(
        "DELETE FROM enrollments WHERE user_id = ? AND course_id = ?",
        (student_id, course_id),
    )
    db.commit()
    flash("Student withdrawn.", "success")
    return redirect(url_for("main.course_detail", course_id=course_id))


# ─── student self-withdraw (only allowed when the course is still ungraded) ──

@main_bp.route("/courses/<int:course_id>/self-withdraw", methods=["POST"])
@role_required("student")
def student_self_withdraw(course_id):
    db = get_db()
    row = db.execute(
        "SELECT grade FROM enrollments WHERE user_id = ? AND course_id = ?",
        (session["user_id"], course_id),
    ).fetchone()
    if not row:
        flash("You're not enrolled in that course.", "error")
        return redirect(url_for("main.dashboard"))
    if row["grade"] is not None and row["grade"] != "":
        flash("This course is already graded — only a TA can remove the enrollment.", "error")
        return redirect(url_for("main.course_detail", course_id=course_id))

    db.execute(
        "DELETE FROM enrollments WHERE user_id = ? AND course_id = ?",
        (session["user_id"], course_id),
    )
    db.commit()
    flash("You have withdrawn from the course.", "success")
    return redirect(url_for("main.dashboard"))


# ─── grading (admin only) ─────────────────────────────────────────
#
# Per the academic policy of CampusPulse: only the admin grades students.
# TAs can manage enrollments (add / withdraw) but cannot set or edit grades.
@main_bp.route("/courses/<int:course_id>/grade", methods=["POST"])
@role_required("admin")
def grade_student(course_id):
    try:
        student_id = int(request.form.get("student_id", "0"))
    except ValueError:
        student_id = 0
    grade = (request.form.get("grade") or "").strip()

    if student_id <= 0 or grade not in ALLOWED_GRADES:
        flash("Invalid request.", "error")
        return redirect(url_for("main.course_detail", course_id=course_id))

    db = get_db()
    # Empty string means clear the grade (mark as ungraded).
    db.execute(
        "UPDATE enrollments SET grade = ? WHERE user_id = ? AND course_id = ?",
        (grade if grade else None, student_id, course_id),
    )
    db.commit()
    if grade:
        flash(f"Grade saved: {grade}", "success")
    else:
        flash("Grade cleared (now ungraded).", "success")
    return redirect(url_for("main.course_detail", course_id=course_id))


# ─── student's own grade report ───────────────────────────────────

@main_bp.route("/my-grades")
@role_required("student")
def my_grades():
    me = _current_user()
    my_courses = _user_courses(me["id"])
    gpa = _student_gpa(me["id"])
    # Compute graded credits / total credits for a 'progress' badge.
    graded_credits = sum(c["credits"] for c in my_courses if c["grade"])
    total_credits  = sum(c["credits"] for c in my_courses)
    return render_template(
        "my_grades.html",
        me=me, my_courses=my_courses, gpa=gpa,
        graded_credits=graded_credits, total_credits=total_credits,
        grade_points=GRADE_POINTS,
    )


# ────────────────────────── admin: users ────────────────────────

@main_bp.route("/admin")
@role_required("ta", "admin")
def admin_hub():
    return redirect(url_for("main.admin_users"))


@main_bp.route("/admin/users")
@role_required("ta", "admin")
def admin_users():
    db = get_db()
    if session["role"] == "ta":
        rows = db.execute(
            "SELECT id, username, email, role, full_name, major, year, gpa "
            "FROM users WHERE role = 'student' ORDER BY full_name"
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id, username, email, role, full_name, major, year, gpa "
            "FROM users WHERE role IN ('student','ta') ORDER BY role DESC, full_name"
        ).fetchall()

    # Attach the right GPA to each row: live-computed for students, stored for TAs.
    users = []
    for r in rows:
        gpa = _display_gpa(r)
        users.append({
            "id": r["id"], "username": r["username"], "email": r["email"],
            "role": r["role"], "full_name": r["full_name"],
            "major": r["major"], "year": r["year"],
            "gpa": gpa,
        })
    return render_template("admin_users.html", users=users)


@main_bp.route("/admin/users/create", methods=["POST"])
@role_required("ta", "admin")
def admin_user_create():
    db = get_db()
    username  = (request.form.get("username")  or "").strip()
    email     = (request.form.get("email")     or "").strip()
    full_name = (request.form.get("full_name") or "").strip()
    password  =  request.form.get("password")  or "Welcome123!"
    role      = (request.form.get("role")      or "student").strip()
    major     = (request.form.get("major")     or "").strip()
    year      = (request.form.get("year")      or "").strip()

    if session["role"] == "ta":
        role = "student"
    elif role not in ("student", "ta"):
        role = "student"

    # Non-students are locked to 'Faculty' for the Year field.
    if role != "student":
        year = "Faculty"

    if not (username and email and full_name):
        flash("Username, email, and full name are required.", "error")
        return redirect(url_for("main.admin_users"))

    exists = db.execute(
        "SELECT 1 FROM users WHERE username = ? OR email = ?",
        (username, email),
    ).fetchone()
    if exists:
        flash("Username or email already taken.", "error")
        return redirect(url_for("main.admin_users"))

    db.execute(
        "INSERT INTO users(username,email,password_hash,role,full_name,bio,major,year)"
        " VALUES (?,?,?,?,?,'',?,?)",
        (username, email, generate_password_hash(password), role, full_name, major, year),
    )
    db.commit()
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("main.admin_users"))


@main_bp.route("/admin/users/<int:user_id>/edit", methods=["POST"])
@role_required("ta", "admin")
def admin_user_edit(user_id):
    db = get_db()
    target = db.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("main.admin_users"))
    if target["role"] == "admin":
        flash("You can't edit an admin.", "error")
        return redirect(url_for("main.admin_users"))
    if session["role"] == "ta" and target["role"] != "student":
        abort(403)

    full_name = (request.form.get("full_name") or "").strip()
    email     = (request.form.get("email")     or "").strip()
    major     = (request.form.get("major")     or "").strip()
    year      = (request.form.get("year")      or "").strip()
    if target["role"] != "student":
        year = "Faculty"

    if not (full_name and email):
        flash("Full name and email are required.", "error")
        return redirect(url_for("main.admin_users"))

    db.execute(
        "UPDATE users SET full_name=?, email=?, major=?, year=? WHERE id=?",
        (full_name, email, major, year, user_id),
    )
    db.commit()
    flash("User updated.", "success")
    return redirect(url_for("main.admin_users"))


@main_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@role_required("ta", "admin")
def admin_user_delete(user_id):
    db = get_db()
    target = db.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("main.admin_users"))
    if target["role"] == "admin":
        flash("You can't delete an admin.", "error")
        return redirect(url_for("main.admin_users"))
    if session["role"] == "ta" and target["role"] != "student":
        abort(403)
    if user_id == session.get("user_id"):
        flash("You can't delete yourself.", "error")
        return redirect(url_for("main.admin_users"))

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash("User deleted.", "success")
    return redirect(url_for("main.admin_users"))


# ─────────────────────────────────────────────────────────────────────────
# ⚠️  VULN #3 — CSRF + MASS-ASSIGNMENT  /admin/users/set-role
# ─────────────────────────────────────────────────────────────────────────
@main_bp.route("/admin/users/set-role", methods=["POST"])
@role_required("admin")
def admin_user_set_role():
    try:
        target_id = int(request.form.get("target_id", "0"))
    except ValueError:
        target_id = 0
    target_role = (request.form.get("target_role") or "").strip()
    # ❌ NO whitelist — accepts 'admin' too.
    if target_id <= 0 or not target_role:
        flash("Invalid request.", "error")
        return redirect(url_for("main.admin_users"))

    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (target_role, target_id))
    db.commit()
    flash(f"User #{target_id} role set to '{target_role}'.", "success")
    return redirect(url_for("main.admin_users"))


# ────────────────────────── admin: courses (admin only) ─────────

@main_bp.route("/admin/courses")
@role_required("admin")
def admin_courses():
    db = get_db()
    rows = db.execute(
        "SELECT id, code, title, credits FROM courses ORDER BY code"
    ).fetchall()
    courses = []
    for c in rows:
        n_enrolled, n_profs = _course_stats(c["id"])
        courses.append({
            "id": c["id"], "code": c["code"], "title": c["title"], "credits": c["credits"],
            "profs": _course_profs(c["id"]),
            "enrolled_count": n_enrolled, "prof_count": n_profs,
        })
    all_profs = db.execute("SELECT id, name FROM professors ORDER BY name").fetchall()
    return render_template("admin_courses.html", courses=courses, all_profs=all_profs)


@main_bp.route("/admin/courses/create", methods=["POST"])
@role_required("admin")
def admin_course_create():
    db = get_db()
    code        = (request.form.get("code")        or "").strip().upper()
    title       = (request.form.get("title")       or "").strip()
    description = (request.form.get("description") or "").strip()
    # `professors_csv` is a comma-separated string of names — supports both
    # typing freeform names and choosing from the datalist.
    profs_csv   = request.form.get("professors_csv") or ""
    try:
        credits = int(request.form.get("credits", "3"))
    except ValueError:
        credits = 3

    if not (code and title):
        flash("Code and title are required.", "error")
        return redirect(url_for("main.admin_courses"))

    exists = db.execute("SELECT 1 FROM courses WHERE code = ?", (code,)).fetchone()
    if exists:
        flash(f"Course code '{code}' already exists.", "error")
        return redirect(url_for("main.admin_courses"))

    cur = db.execute(
        "INSERT INTO courses(code,title,description,credits) VALUES (?,?,?,?)",
        (code, title, description, credits),
    )
    new_id = cur.lastrowid
    _replace_course_profs(new_id, [n for n in profs_csv.split(",") if n.strip()])
    db.commit()
    flash(f"Course '{code}' created.", "success")
    return redirect(url_for("main.admin_courses"))


@main_bp.route("/admin/courses/<int:course_id>/edit", methods=["POST"])
@role_required("admin")
def admin_course_edit(course_id):
    db = get_db()
    title       = (request.form.get("title")       or "").strip()
    description = (request.form.get("description") or "").strip()
    profs_csv   = request.form.get("professors_csv") or ""
    try:
        credits = int(request.form.get("credits", "3"))
    except ValueError:
        credits = 3

    if not title:
        flash("Title is required.", "error")
        return redirect(url_for("main.admin_courses"))

    db.execute(
        "UPDATE courses SET title=?, description=?, credits=? WHERE id=?",
        (title, description, credits, course_id),
    )
    _replace_course_profs(course_id, [n for n in profs_csv.split(",") if n.strip()])
    db.commit()
    flash("Course updated.", "success")
    return redirect(url_for("main.admin_courses"))


@main_bp.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
@role_required("admin")
def admin_course_delete(course_id):
    db = get_db()
    db.execute("DELETE FROM courses WHERE id = ?", (course_id,))
    db.commit()
    flash("Course deleted.", "success")
    return redirect(url_for("main.admin_courses"))


# ────────────────────────── admin: professors (admin only) ──────

@main_bp.route("/admin/professors")
@role_required("admin")
def admin_professors():
    db = get_db()
    rows = db.execute("SELECT id, name FROM professors ORDER BY name").fetchall()
    # For each prof, count how many courses they teach.
    profs = []
    for p in rows:
        n = db.execute(
            "SELECT COUNT(*) FROM course_professors WHERE professor_id = ?", (p["id"],)
        ).fetchone()[0]
        # Course codes they teach.
        course_codes = [c["code"] for c in db.execute(
            "SELECT c.code FROM courses c JOIN course_professors cp ON cp.course_id = c.id "
            "WHERE cp.professor_id = ? ORDER BY c.code",
            (p["id"],),
        ).fetchall()]
        profs.append({"id": p["id"], "name": p["name"], "course_count": n, "codes": course_codes})
    return render_template("admin_professors.html", profs=profs)


@main_bp.route("/admin/professors/create", methods=["POST"])
@role_required("admin")
def admin_professor_create():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("main.admin_professors"))
    db = get_db()
    exists = db.execute("SELECT 1 FROM professors WHERE name = ?", (name,)).fetchone()
    if exists:
        flash("That professor already exists.", "error")
        return redirect(url_for("main.admin_professors"))
    db.execute("INSERT INTO professors(name) VALUES (?)", (name,))
    db.commit()
    flash(f"Professor '{name}' added.", "success")
    return redirect(url_for("main.admin_professors"))


@main_bp.route("/admin/professors/<int:prof_id>/edit", methods=["POST"])
@role_required("admin")
def admin_professor_edit(prof_id):
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("main.admin_professors"))
    db = get_db()
    clash = db.execute("SELECT 1 FROM professors WHERE name = ? AND id != ?", (name, prof_id)).fetchone()
    if clash:
        flash("Another professor with that name already exists.", "error")
        return redirect(url_for("main.admin_professors"))
    db.execute("UPDATE professors SET name = ? WHERE id = ?", (name, prof_id))
    db.commit()
    flash("Professor updated.", "success")
    return redirect(url_for("main.admin_professors"))


@main_bp.route("/admin/professors/<int:prof_id>/delete", methods=["POST"])
@role_required("admin")
def admin_professor_delete(prof_id):
    db = get_db()
    db.execute("DELETE FROM professors WHERE id = ?", (prof_id,))
    db.commit()
    flash("Professor removed.", "success")
    return redirect(url_for("main.admin_professors"))


# ────────────────────────── announcements ───────────────────────
#
# Everyone (student/TA/admin) can post an announcement. The body is rendered
# as plain text (auto-escaped). The optional link_url renders as a click-through
# on the announcement card — this is the in-app delivery channel for the
# Stage-2 reflected-XSS link (instead of "send admin a link via email").
#
# URL safety: link_url must start with http://, https://, or '/' — this prevents
# `javascript:` URLs from turning announcements into an *additional* XSS sink.
# (The reflected XSS sink remains /search?q=... — announcements are just bait.)

def _valid_link_url(u: str) -> bool:
    u = (u or "").strip()
    if not u:
        return True   # empty is fine — link is optional
    return u.startswith(("http://", "https://", "/"))


@main_bp.route("/announcements")
@login_required
def announcements():
    rows = get_db().execute(
        "SELECT a.id, a.title, a.body, a.image_url, a.link_url, a.created_at, "
        "       u.id AS author_id, u.username, u.full_name, u.role "
        "FROM announcements a JOIN users u ON u.id = a.user_id "
        "ORDER BY a.created_at DESC, a.id DESC"
    ).fetchall()
    return render_template("announcements.html", announcements=rows)


@main_bp.route("/announcements/new", methods=["GET", "POST"])
@login_required
def announcement_new():
    if request.method == "POST":
        title     = (request.form.get("title")     or "").strip()
        body      = (request.form.get("body")      or "").strip()
        image_url = (request.form.get("image_url") or "").strip() or None
        link_url  = (request.form.get("link_url")  or "").strip() or None

        if not (title and body):
            flash("Title and body are required.", "error")
            return render_template("announcement_new.html",
                                   title=title, body=body,
                                   image_url=image_url or "", link_url=link_url or "")

        if image_url and not _valid_link_url(image_url):
            flash("Image URL must start with http://, https://, or /", "error")
            return render_template("announcement_new.html",
                                   title=title, body=body,
                                   image_url=image_url, link_url=link_url or "")
        if link_url and not _valid_link_url(link_url):
            flash("Link URL must start with http://, https://, or /", "error")
            return render_template("announcement_new.html",
                                   title=title, body=body,
                                   image_url=image_url or "", link_url=link_url)

        db = get_db()
        db.execute(
            "INSERT INTO announcements(user_id, title, body, image_url, link_url) "
            "VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], title, body, image_url, link_url),
        )
        db.commit()
        flash("Announcement posted.", "success")
        return redirect(url_for("main.announcements"))

    return render_template("announcement_new.html",
                           title="", body="", image_url="", link_url="")


def _can_edit_announcement(author_row, me_role, me_id):
    """Only the author may edit their own announcement."""
    return author_row["user_id"] == me_id


def _can_delete_announcement(author_role, me_role, me_id, author_id):
    """Delete permissions:
       • author can always delete their own
       • admin can delete anything
       • TA can delete students' announcements (but not admin/TA posts)"""
    if author_id == me_id:
        return True
    if me_role == "admin":
        return True
    if me_role == "ta" and author_role == "student":
        return True
    return False


@main_bp.route("/announcements/<int:ann_id>/edit", methods=["GET", "POST"])
@login_required
def announcement_edit(ann_id):
    db = get_db()
    ann = db.execute(
        "SELECT id, user_id, title, body, image_url, link_url FROM announcements WHERE id = ?",
        (ann_id,),
    ).fetchone()
    if not ann:
        flash("Announcement not found.", "error")
        return redirect(url_for("main.announcements"))
    if not _can_edit_announcement(ann, session.get("role"), session.get("user_id")):
        abort(403)

    if request.method == "POST":
        title     = (request.form.get("title")     or "").strip()
        body      = (request.form.get("body")      or "").strip()
        image_url = (request.form.get("image_url") or "").strip() or None
        link_url  = (request.form.get("link_url")  or "").strip() or None

        if not (title and body):
            flash("Title and body are required.", "error")
            return render_template("announcement_edit.html", ann=ann,
                                   title=title, body=body,
                                   image_url=image_url or "", link_url=link_url or "")
        if image_url and not _valid_link_url(image_url):
            flash("Image URL must start with http://, https://, or /", "error")
            return render_template("announcement_edit.html", ann=ann,
                                   title=title, body=body,
                                   image_url=image_url, link_url=link_url or "")
        if link_url and not _valid_link_url(link_url):
            flash("Link URL must start with http://, https://, or /", "error")
            return render_template("announcement_edit.html", ann=ann,
                                   title=title, body=body,
                                   image_url=image_url or "", link_url=link_url)

        db.execute(
            "UPDATE announcements SET title=?, body=?, image_url=?, link_url=? WHERE id=?",
            (title, body, image_url, link_url, ann_id),
        )
        db.commit()
        flash("Announcement updated.", "success")
        return redirect(url_for("main.announcements"))

    return render_template("announcement_edit.html", ann=ann,
                           title=ann["title"], body=ann["body"],
                           image_url=ann["image_url"] or "",
                           link_url=ann["link_url"] or "")


@main_bp.route("/announcements/<int:ann_id>/delete", methods=["POST"])
@login_required
def announcement_delete(ann_id):
    db = get_db()
    row = db.execute(
        "SELECT a.user_id, u.role AS author_role "
        "FROM announcements a JOIN users u ON u.id = a.user_id "
        "WHERE a.id = ?", (ann_id,),
    ).fetchone()
    if not row:
        flash("Announcement not found.", "error")
        return redirect(url_for("main.announcements"))
    if not _can_delete_announcement(
        row["author_role"], session.get("role"), session.get("user_id"), row["user_id"]
    ):
        abort(403)
    db.execute("DELETE FROM announcements WHERE id = ?", (ann_id,))
    db.commit()
    flash("Announcement deleted.", "success")
    return redirect(url_for("main.announcements"))
