"""Create campuspulse.db with schema + seed users + courses + professors + enrollments.

Run once before `python run.py`. Re-running drops & recreates everything.

Schema:
    users              — accounts (student | ta | admin)
    professors         — instructor pool
    courses            — course catalog
    course_professors  — many-to-many: who teaches what
    enrollments        — student ↔ course, with the specific lecturer and a grade
                         (grade NULL means 'ungraded')
"""
import os
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "campuspulse.db"

SCHEMA = """
DROP TABLE IF EXISTS enrollments;
DROP TABLE IF EXISTS course_professors;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS professors;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('student', 'ta', 'admin')),
    full_name     TEXT NOT NULL,
    bio           TEXT NOT NULL DEFAULT '',
    major         TEXT NOT NULL DEFAULT '',
    year          TEXT NOT NULL DEFAULT '',
    gpa           REAL                       -- TAs: pre-grad GPA (seeded);
                                             -- students: NULL (computed live)
);

CREATE TABLE professors (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE courses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT UNIQUE NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    credits     INTEGER NOT NULL DEFAULT 3
);

CREATE TABLE course_professors (
    course_id    INTEGER NOT NULL,
    professor_id INTEGER NOT NULL,
    PRIMARY KEY (course_id, professor_id),
    FOREIGN KEY (course_id)    REFERENCES courses(id)    ON DELETE CASCADE,
    FOREIGN KEY (professor_id) REFERENCES professors(id) ON DELETE CASCADE
);

CREATE TABLE enrollments (
    user_id      INTEGER NOT NULL,
    course_id    INTEGER NOT NULL,
    professor_id INTEGER,                    -- which lecturer the student is with
    grade        TEXT,                       -- A+, A, A-, B+, B, B-, C+, C, C-, D+, D, F or NULL
    PRIMARY KEY (user_id, course_id),
    FOREIGN KEY (user_id)      REFERENCES users(id)       ON DELETE CASCADE,
    FOREIGN KEY (course_id)    REFERENCES courses(id)     ON DELETE CASCADE,
    FOREIGN KEY (professor_id) REFERENCES professors(id)  ON DELETE SET NULL
);

CREATE TABLE announcements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    image_url  TEXT,                          -- optional embedded image
    link_url   TEXT,                          -- optional click-through URL (http/https/relative only)
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

# (username, email, password, role, full_name, bio, major, year, gpa)
# GPA is the *stored* pre-grad GPA for TAs; for students it stays NULL and is
# computed live from their grades. For admin/faculty it's also NULL (N/A).
SEED_USERS = [
    ("Dairo",   "dairo8@campuspulse.edu",     "Dairo123!",   "admin",
        "Prof. Mohamed Eldairouty",
        "Computer Engineering department. Oversees the CampusPulse portal.",
        "Computer Engineering", "Faculty", None),

    ("Mariam",  "mariamash@campuspulse.edu",  "Mariam123!",  "ta",
        "Mariam Ashraf",
        "Teaching Assistant — interested in AI and Mobile Dev.",
        "Computer Engineering", "Faculty", 4.0),

    ("Nayrouz", "nayro@campuspulse.edu",      "Nayrouz123!", "ta",
        "Nayrouz Ahmed",
        "Teaching Assistant — interested in AI and Web Dev.",
        "Computer Engineering", "Faculty", 4.0),

    ("Negm",    "negm24@campuspulse.edu",     "Negm123!",    "student",
        "Youssef Negm",
        "CE senior — interested in hacking and security.",
        "Computer Engineering", "Year 4", None),
]

SEED_PROFESSORS = [
    "Dr. Sherine Youssef",
    "Dr. Noha Seddik",
    "Dr. Amani Saad",
    "Dr. Soha",
    "Dr. Karma",
    "Dr. Marwa Elshenawy",
    "Dr. Mohamed Samir",
    "Dr. Hany Fouad",
    "Dr. Ahmed Hassan",
]

# (code, title, description, credits, [professor names])
SEED_COURSES = [
    ("CSC101", "Introduction to Programming",
        "Foundations of programming using Python. Variables, loops, functions, basic data structures.",
        3, ["Dr. Sherine Youssef"]),
    ("CSC205", "Data Structures & Algorithms",
        "Arrays, linked lists, trees, graphs, sorting and searching. Complexity analysis.",
        4, ["Dr. Noha Seddik", "Dr. Ahmed Hassan"]),
    ("CSC310", "Database Systems",
        "Relational model, SQL, indexing, transactions, normalization.",
        3, ["Dr. Amani Saad"]),
    ("CSC401", "Web Application Security",
        "OWASP Top 10 — SQLi, XSS, CSRF, auth flaws. Hands-on offensive & defensive labs.",
        3, ["Dr. Soha", "Dr. Mohamed Samir"]),
    ("CSC420", "Artificial Intelligence",
        "Search algorithms, knowledge representation, machine-learning fundamentals.",
        3, ["Dr. Karma"]),
    ("ECE211", "Digital Logic Design",
        "Boolean algebra, combinational & sequential circuits, FPGAs.",
        3, ["Dr. Marwa Elshenawy"]),
    ("ECE330", "Computer Networks",
        "OSI/TCP-IP stack, routing, transport-layer protocols, network security basics.",
        3, ["Dr. Mohamed Samir"]),
    ("MAT201", "Linear Algebra",
        "Vectors, matrices, eigenvalues, applications in graphics & ML.",
        3, ["Dr. Hany Fouad"]),
]

# Per-student enrollment list: (course_code, professor_name, grade-or-None)
# professor_name may be None only when the course has exactly one lecturer
# (the seeder will resolve it). A None grade means 'ungraded'.
ENROLLMENTS_BY_STUDENT = {
    "Negm": [
        ("CSC205", "Dr. Noha Seddik",    "A-"),    # co-taught course — pick a lecturer
        ("CSC310", None,                 "B+"),    # only one prof — auto-resolved
        ("CSC401", "Dr. Soha",           None),    # co-taught + ungraded
        ("ECE330", None,                 None),    # single prof + ungraded
    ],
}

# (author_username, title, body, image_url, link_url) — seed announcements feed.
SEED_ANNOUNCEMENTS = [
    ("Dairo",
     "Welcome back to CampusPulse 🎉",
     "Welcome to the new semester. Please review the updated academic calendar "
     "and make sure your course registrations are finalized by the end of next week. "
     "TAs are available during office hours to assist with enrollment.",
     "/static/img/schedule.png",
     None),

    ("Mariam",
     "📚 Study group: CSC401 — Web App Security",
     "I'll be running a weekly study group for CSC401 every Tuesday at 4pm in Lab B. "
     "We'll cover the OWASP Top 10 and walk through hands-on labs. Drop by if interested!",
     None,
     None),
]


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[seed] removed existing {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    for username, email, password, role, full_name, bio, major, year, gpa in SEED_USERS:
        conn.execute(
            "INSERT INTO users(username,email,password_hash,role,full_name,bio,major,year,gpa)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (username, email, generate_password_hash(password), role, full_name, bio, major, year, gpa),
        )

    for name in SEED_PROFESSORS:
        conn.execute("INSERT INTO professors(name) VALUES (?)", (name,))

    for code, title, description, credits, _profs in SEED_COURSES:
        conn.execute(
            "INSERT INTO courses(code,title,description,credits) VALUES (?,?,?,?)",
            (code, title, description, credits),
        )

    user_ids   = {r[1]: r[0] for r in conn.execute("SELECT id, username FROM users").fetchall()}
    course_ids = {r[1]: r[0] for r in conn.execute("SELECT id, code FROM courses").fetchall()}
    prof_ids   = {r[1]: r[0] for r in conn.execute("SELECT id, name FROM professors").fetchall()}

    for code, _title, _desc, _cr, profs in SEED_COURSES:
        for pname in profs:
            conn.execute(
                "INSERT INTO course_professors(course_id, professor_id) VALUES (?, ?)",
                (course_ids[code], prof_ids[pname]),
            )

    # Resolve enrollments — if professor name is None, look up the single
    # professor assigned to the course and use that.
    n_enrollments = 0
    # Seed announcements.
    for author, title, body, image_url, link_url in SEED_ANNOUNCEMENTS:
        conn.execute(
            "INSERT INTO announcements(user_id, title, body, image_url, link_url) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_ids[author], title, body, image_url, link_url),
        )

    for username, items in ENROLLMENTS_BY_STUDENT.items():
        uid = user_ids[username]
        for code, prof_name, grade in items:
            cid = course_ids[code]
            if prof_name is None:
                row = conn.execute(
                    "SELECT professor_id FROM course_professors WHERE course_id = ?", (cid,)
                ).fetchone()
                pid = row[0] if row else None
            else:
                pid = prof_ids.get(prof_name)
            conn.execute(
                "INSERT INTO enrollments(user_id, course_id, professor_id, grade) VALUES (?,?,?,?)",
                (uid, cid, pid, grade),
            )
            n_enrollments += 1

    conn.commit()
    conn.close()
    n_cp = sum(len(p) for _, _, _, _, p in SEED_COURSES)
    print(f"[seed] created {DB_PATH}")
    print(f"[seed]   users:              {len(SEED_USERS)}")
    print(f"[seed]   professors:         {len(SEED_PROFESSORS)}")
    print(f"[seed]   courses:            {len(SEED_COURSES)}")
    print(f"[seed]   course-prof links:  {n_cp}")
    print(f"[seed]   enrollments:        {n_enrollments}")
    print("[seed] login credentials:")
    for u, _, p, role, *_ in SEED_USERS:
        print(f"        {role:<8} {u:<10} {p}")


if __name__ == "__main__":
    main()
