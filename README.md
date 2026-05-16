<p align="center">
  <img src="assets/logo/logo.png" alt="CampusPulse-Shield Logo" width="220"/>
</p>

<h1 align="center">🛡️ CampusPulse-Shield</h1>

<p align="center">
  🎯 Chained Vulnerability Lab &nbsp;•&nbsp; SQLi → Reflected XSS → CSRF &nbsp;•&nbsp; 🔴 Vulnerable vs 🟢 Hardened
  <br/>
  🎓 <em>Cyber Security Course Project — ECE5303</em>
  <br/>
  🔗 Based on the original <a href="https://github.com/Negm24/CampusPulse">CampusPulse</a> student portal (Web Development course)
</p>

---

> 🛡️ A university student portal rebuilt as a security lab. Attack the vulnerable version, watch the same attack die on the hardened one.

---

## 🧠 Overview

CampusPulse-Shield ships in two parallel deployments:

- 🔴 **Vulnerable** — three real, exploitable flaws chained end-to-end
- 🟢 **Hardened** — same UI, same features, every flaw patched with its textbook fix

**The chain:**
> 🔍 SQL Injection (recon) → 💉 Reflected XSS (delivery) → 🪤 CSRF (escalation)
>
> End goal: a regular student promotes themselves to **admin** without ever knowing the admin's password.

---

## 🎯 The Attack Chain

| Stage | Vulnerability | What happens |
|-------|--------------|-------------|
| 1️⃣ | 🔍 SQL Injection | Attacker extracts the admin's username & email from the database via the search bar |
| 2️⃣ | 💉 Reflected XSS | A crafted link tricks the admin into running the attacker's script in their browser |
| 3️⃣ | 🪤 CSRF | That script silently fires a request that promotes the attacker's account to admin |

---

## 🛡️ The Fixes

| Stage | Fix |
|-------|-----|
| SQLi | Parameterized queries — input never touches SQL logic |
| XSS | Jinja2 auto-escaping + strict CSP header |
| CSRF | Per-session token on every state-changing form + `SameSite=Lax` cookies |

---

## 👤 Role Model

| Role | Permissions |
|------|-------------|
| 🎓 Student | Own profile, grades, course search, self-withdrawal from ungraded courses |
| 🧑‍🏫 TA | Manage students & enrollments, read-only grades |
| 👑 Admin | Full control — grading, role changes, course & professor management |

---

## 🚀 Quick Start

> Requires Python 3.10+. No Node, no Docker, no MySQL.

```bash
# Vulnerable build 🔴
cd vulnerable && pip install -r requirements.txt
python seed.py && python run.py   # → http://localhost:5000

# Hardened build 🟢 (new terminal)
cd mitigated && pip install -r requirements.txt
python seed.py && python run.py   # → http://localhost:5001
```

**Seed accounts:**

| Role | Username | Password |
|------|----------|----------|
| 👑 Admin | `Dairo` | `Dairo123!` |
| 🧑‍🏫 TA | `Mariam` | `Mariam123!` |
| 🧑‍🏫 TA | `Nayrouz` | `Nayrouz123!` |
| 🎓 Student | `Negm` | `Negm123!` |

> The attacker starts as **Negm** and ends the demo as **admin** — without ever touching `Dairo123!`.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10+ · Flask |
| Database | SQLite + raw `sqlite3` |
| Templating | Jinja2 (server-rendered) |
| Frontend | Plain HTML / CSS / minimal JS |

---

## 📸 Application Preview

### 🔐 Login Page

<p align="center">
  <img src="assets/screenshots/login.png" alt="CampusPulse-Shield login page" width="78%"/>
</p>

---

### 🏠 Dashboard — Three Roles, One Page

<table>
  <tr>
    <td align="center" width="33%">
      <a href="assets/screenshots/dashboard-student.png">
        <img src="assets/screenshots/dashboard-student.png" alt="Student dashboard (Negm)"/>
      </a>
      <br/>
      <sub><b>🎓 Student — Negm</b></sub>
    </td>
    <td align="center" width="33%">
      <a href="assets/screenshots/dashboard-ta.png">
        <img src="assets/screenshots/dashboard-ta.png" alt="TA dashboard"/>
      </a>
      <br/>
      <sub><b>🧑‍🏫 TA — Nayrouz / Mariam</b></sub>
    </td>
    <td align="center" width="33%">
      <a href="assets/screenshots/dashboard-admin.png">
        <img src="assets/screenshots/dashboard-admin.png" alt="Admin dashboard (Dairo)"/>
      </a>
      <br/>
      <sub><b>👑 Admin — Dairo</b></sub>
    </td>
  </tr>
</table>

---

## 👥 Team

| Name | ID |
|------|----|
| **Nayrouz Ahmed** | 221011969 |
| **Mariam Ashraf** | 221002547 |
| **[@Mohamed Abdallah Eldairouty](https://github.com/MohamedEldairouty)** | 221001719 |
| **[@Youssef Negm](https://github.com/Negm24)** | 221011914 |

---

## 📄 Report & Demo

- 📖 Full technical report: [`docs/report.pdf`](docs/report.pdf)
- 🎥 Demo video: [`assets/demo/full-demo.mp4`](assets/demo/full-demo.mp4)

---

<p align="center">🛡️ <strong>CampusPulse-Shield</strong> — Break it on purpose. Patch it on principle.</p>
