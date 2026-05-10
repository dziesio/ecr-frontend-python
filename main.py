import os
import secrets
import uuid
from contextlib import asynccontextmanager

import asyncpg
import bcrypt
import httpx
from fastapi import FastAPI, Form, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# ── Config ────────────────────────────────────────────────────────────────────

DATABASE_URL     = os.getenv("DATABASE_URL",     "postgresql://postgres:postgres@postgres:5432/ecr_harvester")
ECR_API_BASE_URL = os.getenv("ECR_API_BASE_URL", "http://ecr-api:8081")
SECRET_KEY       = os.getenv("SECRET_KEY",       "change-me-" + secrets.token_hex(16))

# ── Globals ───────────────────────────────────────────────────────────────────

pool:        asyncpg.Pool        | None = None
http_client: httpx.AsyncClient   | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool, http_client
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)
    http_client = httpx.AsyncClient(base_url=ECR_API_BASE_URL, timeout=10)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS app_users (
            id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            username              VARCHAR(50) UNIQUE NOT NULL,
            password_hash         VARCHAR(255) NOT NULL,
            role                  VARCHAR(10)  NOT NULL DEFAULT 'USER',
            force_password_change BOOLEAN      NOT NULL DEFAULT FALSE,
            created_at            TIMESTAMP    NOT NULL DEFAULT NOW()
        )
    """)

    if not await pool.fetchval("SELECT 1 FROM app_users WHERE username = 'admin'"):
        pw = bcrypt.hashpw(b"admin", bcrypt.gensalt(12)).decode()
        await pool.execute(
            "INSERT INTO app_users (username, password_hash, role) VALUES ('admin', $1, 'ADMIN')", pw
        )

    yield
    await pool.close()
    await http_client.aclose()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=False)

import re as _re
templates = Jinja2Templates(directory="templates")
templates.env.filters["dt"]    = lambda v: str(v)[:16].replace("T", " ") if v else ""
templates.env.filters["date"]  = lambda v: v.strftime("%Y-%m-%d") if hasattr(v, "strftime") else (str(v)[:10] if v else "—")
templates.env.filters["clean"] = lambda v: _re.sub(r'\n{3,}', '\n\n', v.strip()) if v else ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def current_user(request: Request) -> dict | None:
    if "username" not in request.session:
        return None
    return {
        "username":              request.session["username"],
        "role":                  request.session["role"],
        "id":                    request.session["user_id"],
        "force_password_change": request.session.get("force_password_change", False),
    }


def flash(request: Request, key: str, msg: str):
    request.session[f"_flash_{key}"] = msg


def pop_flash(request: Request, key: str) -> str | None:
    return request.session.pop(f"_flash_{key}", None)


def ctx(request: Request, user, **kw):
    return {"request": request, "user": user, **kw}


async def api_get(path: str):
    r = await http_client.get(path)
    r.raise_for_status()
    return r.json()


# ── Auth ──────────────────────────────────────────────────────────────────────

def _check_auth(request: Request) -> dict | None:
    user = current_user(request)
    if user is None:
        return None
    if user["force_password_change"] and not request.url.path.startswith("/profile"):
        return "force_change"
    return user


# ── Routes: auth ──────────────────────────────────────────────────────────────

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error":   pop_flash(request, "error"),
        "logout":  "logout" in request.query_params,
    })


@app.post("/login")
async def login_submit(request: Request,
                       username: str = Form(...), password: str = Form(...)):
    row = await pool.fetchrow("SELECT * FROM app_users WHERE username = $1", username)
    if row and bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        request.session["username"]              = row["username"]
        request.session["role"]                  = row["role"]
        request.session["user_id"]               = str(row["id"])
        request.session["force_password_change"] = row["force_password_change"]
        return RedirectResponse("/", status_code=302)
    flash(request, "error", "Invalid username or password.")
    return RedirectResponse("/login", status_code=302)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login?logout", status_code=302)


# ── Routes: main ──────────────────────────────────────────────────────────────

@app.get("/")
async def index(request: Request):
    user = _check_auth(request)
    if user is None:        return RedirectResponse("/login",   status_code=302)
    if user == "force_change": return RedirectResponse("/profile", status_code=302)

    api_error = pop_flash(request, "api_error")
    try:
        students = await api_get("/api/students")
    except Exception:
        students  = []
        api_error = "Could not reach ecr-api. Make sure it is running."

    return templates.TemplateResponse("index.html", ctx(request, user,
        students=students, api_error=api_error))


@app.get("/student/{student_id}")
async def student_page(request: Request, student_id: str):
    user = _check_auth(request)
    if user is None:        return RedirectResponse("/login",   status_code=302)
    if user == "force_change": return RedirectResponse("/profile", status_code=302)

    try:
        student       = await api_get(f"/api/students/{student_id}")
        grades        = await api_get(f"/api/students/{student_id}/grades")
        messages      = await api_get(f"/api/students/{student_id}/messages")
        attendance    = await api_get(f"/api/students/{student_id}/attendance")
        announcements = await api_get(f"/api/students/{student_id}/announcements")
    except Exception as e:
        flash(request, "api_error", f"Could not load student data: {e}")
        return RedirectResponse("/", status_code=302)

    inbox = [m for m in messages if m.get("messageType") == "INBOX"]
    sent  = [m for m in messages if m.get("messageType") == "SENT"]

    return templates.TemplateResponse("student.html", ctx(request, user,
        student=student, grades=grades,
        inbox=inbox, sent=sent, messages=messages,
        attendance=attendance, announcements=announcements))


# ── Routes: profile ───────────────────────────────────────────────────────────

@app.get("/profile")
async def profile_page(request: Request):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("profile.html", ctx(request, user,
        error=pop_flash(request, "error"), success=pop_flash(request, "success")))


@app.post("/profile/password")
async def change_password(request: Request,
                          currentPassword: str = Form(...),
                          newPassword:     str = Form(...),
                          confirmPassword: str = Form(...)):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=302)

    if newPassword != confirmPassword:
        flash(request, "error", "New passwords do not match.")
        return RedirectResponse("/profile", status_code=302)
    if len(newPassword) < 8:
        flash(request, "error", "New password must be at least 8 characters.")
        return RedirectResponse("/profile", status_code=302)

    row = await pool.fetchrow("SELECT password_hash FROM app_users WHERE username = $1", user["username"])
    if not row or not bcrypt.checkpw(currentPassword.encode(), row["password_hash"].encode()):
        flash(request, "error", "Current password is incorrect.")
        return RedirectResponse("/profile", status_code=302)

    new_hash = bcrypt.hashpw(newPassword.encode(), bcrypt.gensalt(12)).decode()
    await pool.execute(
        "UPDATE app_users SET password_hash = $1, force_password_change = FALSE WHERE username = $2",
        new_hash, user["username"])
    request.session["force_password_change"] = False
    return RedirectResponse("/", status_code=302)


# ── Routes: admin ─────────────────────────────────────────────────────────────

@app.get("/admin/users")
async def admin_users(request: Request):
    user = _check_auth(request)
    if user is None or user == "force_change": return RedirectResponse("/login", status_code=302)
    if user["role"] != "ADMIN":               return RedirectResponse("/",      status_code=302)

    rows = await pool.fetch("SELECT * FROM app_users ORDER BY created_at")
    return templates.TemplateResponse("admin/users.html", ctx(request, user,
        users=[dict(r) for r in rows],
        success=pop_flash(request, "success"),
        error=pop_flash(request, "error")))


@app.post("/admin/users")
async def create_user(request: Request,
                      username: str = Form(...),
                      password: str = Form(...),
                      role:     str = Form(...)):
    user = _check_auth(request)
    if user is None or user == "force_change" or user["role"] != "ADMIN":
        return RedirectResponse("/login", status_code=302)

    role = role.upper()
    if role not in ("USER", "ADMIN"):
        flash(request, "error", "Invalid role.")
        return RedirectResponse("/admin/users", status_code=302)
    if await pool.fetchval("SELECT 1 FROM app_users WHERE username = $1", username):
        flash(request, "error", f"Username '{username}' already exists.")
        return RedirectResponse("/admin/users", status_code=302)

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    await pool.execute(
        "INSERT INTO app_users (username, password_hash, role, force_password_change) VALUES ($1,$2,$3,TRUE)",
        username, pw_hash, role)
    flash(request, "success",
          f"User '{username}' created. They will be required to change their password on first login.")
    return RedirectResponse("/admin/users", status_code=302)


@app.post("/admin/users/{user_id}/delete")
async def delete_user(request: Request, user_id: str):
    user = _check_auth(request)
    if user is None or user == "force_change" or user["role"] != "ADMIN":
        return RedirectResponse("/login", status_code=302)

    row = await pool.fetchrow("SELECT username FROM app_users WHERE id = $1", uuid.UUID(user_id))
    if not row:
        flash(request, "error", "User not found.")
        return RedirectResponse("/admin/users", status_code=302)
    if row["username"] == user["username"]:
        flash(request, "error", "You cannot delete your own account.")
        return RedirectResponse("/admin/users", status_code=302)

    await pool.execute("DELETE FROM app_users WHERE id = $1", uuid.UUID(user_id))
    flash(request, "success", "User deleted.")
    return RedirectResponse("/admin/users", status_code=302)


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
