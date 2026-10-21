import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import config, graph

if not config.API_KEY or not config.UI_PASSWORD:
    raise RuntimeError("API_KEY and UI_PASSWORD must be set (refusing to start unauthenticated).")
if not config.DRY_RUN and not (config.TENANT_ID and config.CLIENT_ID
                               and (config.CLIENT_SECRET or config.CERT_PRIVATE_KEY_PATH
                                    or config.CERT_PRIVATE_KEY)):
    raise RuntimeError("TENANT_ID, CLIENT_ID and a secret/certificate are required unless DRY_RUN=true.")

app = FastAPI(title="M365 Provisioner")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
basic = HTTPBasic()


# ---------- DB ----------
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


with db() as _c:
    _c.execute("""CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        ticket_id TEXT NOT NULL,
        status TEXT NOT NULL,            -- pending|approved|completed|failed|rejected
        payload TEXT NOT NULL,           -- request JSON (password stripped)
        password TEXT,                   -- temp password; nulled after agent reads it once
        result TEXT,                     -- result JSON
        approved_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL)""")
    _c.execute("CREATE INDEX IF NOT EXISTS ix_ticket ON requests(ticket_id)")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------- auth ----------
def require_api_key(authorization: Optional[str] = Header(None), x_api_key: Optional[str] = Header(None)):
    supplied = x_api_key or (authorization[7:] if authorization and authorization.startswith("Bearer ") else "")
    if not secrets.compare_digest(supplied.encode(), config.API_KEY.encode()):
        raise HTTPException(401, "Invalid API key")


def require_ui_user(request: Request, creds: HTTPBasicCredentials = Depends(basic)) -> str:
    ok = (secrets.compare_digest(creds.username.encode(), config.UI_USERNAME.encode())
          & secrets.compare_digest(creds.password.encode(), config.UI_PASSWORD.encode()))
    if not ok:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Basic"})
    # Basic auth is attached automatically by browsers, so block cross-site form posts (CSRF).
    if request.method == "POST" and request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        raise HTTPException(403, "Cross-site request blocked")
    return creds.username


# ---------- models ----------
class NewUser(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=64)
    display_name: Optional[str] = Field(None, max_length=128)
    given_name: str = Field(..., min_length=1, max_length=64)
    surname: str = Field(..., min_length=1, max_length=64)
    user_principal_name: str = Field(..., pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9.-]+$")
    department: Optional[str] = None
    job_title: Optional[str] = None
    employee_id: Optional[str] = Field(None, max_length=64)
    usage_location: Optional[str] = Field(None, pattern=r"^[A-Z]{2}$")
    license: Optional[str] = Field(None, description="SKU part number or GUID, e.g. SPB")


# ---------- core ----------
def execute(request_id: str) -> None:
    with db() as c:
        row = c.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
    payload = json.loads(row["payload"])
    password = graph.generate_password()
    try:
        if config.DRY_RUN:
            res = {"object_id": str(uuid.uuid4()), "dry_run": True, "warnings": [],
                   "user_principal_name": payload["user_principal_name"]}
        else:
            res = graph.create_user(payload, password)
        status = "completed"
        res.update({"display_name": payload["display_name"],
                    "must_change_password": True})
        pw = password
    except Exception as e:  # noqa: BLE001 - surface any failure to the ticket
        status, res, pw = "failed", {"error": str(e)}, None
    with db() as c:
        c.execute("UPDATE requests SET status=?, result=?, password=?, updated_at=? WHERE id=?",
                  (status, json.dumps(res), pw, now(), request_id))


def approve(request_id: str, who: str) -> None:
    with db() as c:  # atomic pending->approved so a double click can't create twice
        cur = c.execute("UPDATE requests SET status='approved', approved_by=?, updated_at=? "
                        "WHERE id=? AND status='pending'", (who, now(), request_id))
        if cur.rowcount != 1:
            raise HTTPException(409, "Request is not pending")
    execute(request_id)


def public_view(row: sqlite3.Row, reveal_password: bool = False) -> Dict[str, Any]:
    out = {"id": row["id"], "ticket_id": row["ticket_id"], "status": row["status"],
           "request": json.loads(row["payload"]), "approved_by": row["approved_by"],
           "created_at": row["created_at"], "updated_at": row["updated_at"]}
    if row["result"]:
        out["result"] = json.loads(row["result"])
        if reveal_password and row["status"] == "completed" and row["password"]:
            out["result"]["temporary_password"] = row["password"]
    return out


# ---------- agent API ----------
@app.post("/api/requests", status_code=201, dependencies=[Depends(require_api_key)])
def submit(body: NewUser):
    payload = body.model_dump() if hasattr(body, "model_dump") else body.dict()
    payload["user_principal_name"] = payload["user_principal_name"].lower()
    domain = payload["user_principal_name"].split("@", 1)[1]
    if domain not in config.ALLOWED_DOMAINS:
        raise HTTPException(422, "UPN domain must be one of %s" % config.ALLOWED_DOMAINS)
    payload["usage_location"] = payload["usage_location"] or config.DEFAULT_USAGE_LOCATION
    payload["display_name"] = payload["display_name"] or "%s %s" % (payload["given_name"], payload["surname"])

    with db() as c:
        # Idempotency: the same ticket never creates two requests unless the earlier one was rejected/failed.
        dup = c.execute("SELECT * FROM requests WHERE ticket_id=? AND status NOT IN ('rejected','failed') "
                        "ORDER BY created_at DESC", (payload["ticket_id"],)).fetchone()
        if dup:
            return public_view(dup)
        rid = str(uuid.uuid4())
        c.execute("INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?)",
                  (rid, payload["ticket_id"], "pending", json.dumps(payload), None, None, None, now(), now()))
    if config.AUTO_APPROVE:
        approve(rid, "auto")
    with db() as c:
        return public_view(c.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone())


@app.get("/api/requests/{request_id}", dependencies=[Depends(require_api_key)])
def get_request(request_id: str):
    """Poll this. When status is 'completed' the temp password is included ONCE, then erased."""
    with db() as c:
        row = c.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Not found")
        out = public_view(row, reveal_password=True)
        if row["status"] == "completed" and row["password"]:
            c.execute("UPDATE requests SET password=NULL WHERE id=?", (request_id,))
        return out


@app.get("/api/requests", dependencies=[Depends(require_api_key)])
def find_by_ticket(ticket_id: str):
    with db() as c:
        rows = c.execute("SELECT * FROM requests WHERE ticket_id=? ORDER BY created_at DESC", (ticket_id,)).fetchall()
    return [public_view(r) for r in rows]  # never reveals passwords; use GET /{id} for that


# ---------- approval UI ----------
@app.get("/")
def index(request: Request, user: str = Depends(require_ui_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM requests ORDER BY (status='pending') DESC, created_at DESC LIMIT 200").fetchall()
    items = [public_view(r) for r in rows]
    return templates.TemplateResponse(request, "index.html", {"items": items,
                                                       "auto": config.AUTO_APPROVE, "dry": config.DRY_RUN})


@app.get("/requests/{request_id}")
def detail(request: Request, request_id: str, user: str = Depends(require_ui_user)):
    with db() as c:
        row = c.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Not found")
    return templates.TemplateResponse(request, "detail.html", {"r": public_view(row),
                                                        "json": json.dumps(public_view(row), indent=2)})


@app.post("/requests/{request_id}/approve")
def ui_approve(request_id: str, user: str = Depends(require_ui_user)):
    approve(request_id, user)
    return RedirectResponse("/requests/" + request_id, status_code=303)


@app.post("/requests/{request_id}/reject")
def ui_reject(request_id: str, user: str = Depends(require_ui_user)):
    with db() as c:
        cur = c.execute("UPDATE requests SET status='rejected', approved_by=?, password=NULL, updated_at=? "
                        "WHERE id=? AND status='pending'", (user, now(), request_id))
        if cur.rowcount != 1:
            raise HTTPException(409, "Request is not pending")
    return RedirectResponse("/requests/" + request_id, status_code=303)
