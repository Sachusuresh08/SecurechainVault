import os
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from blockchain import init_chain, append_block, verify_chain

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "users.db")
STORAGE_DIR = os.environ.get("STORAGE_DIR", os.path.join(BASE_DIR, "storage"))

APPROVAL_QUORUM = int(os.environ.get("APPROVAL_QUORUM", "2"))
ALLOWED_ROLES = {"user", "staff", "admin"}
APPROVER_ROLES = {"staff", "admin"}
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))

app = Flask(__name__)

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True

app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_ME_" + secrets.token_hex(16))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

os.makedirs(STORAGE_DIR, exist_ok=True)

# --- Helpers ---
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]

def require_csrf():
    token = request.form.get("csrf")
    if not token or token != session.get("csrf"):
        abort(400, description="CSRF validation failed.")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            flash("Please log in.", "bad")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def role_required(*roles):
    roleset = set(roles)
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roleset:
                flash("Access denied.", "bad")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# --- Database Init ---
def init_db():
    conn = db_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            orig_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            mimetype TEXT,
            sha256 TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT NOT NULL,
            action TEXT NOT NULL,
            file_id INTEGER,
            orig_filename TEXT,
            mimetype TEXT,
            sha256 TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS request_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            approver TEXT NOT NULL,
            decision TEXT NOT NULL,
            decided_at TEXT NOT NULL,
            UNIQUE(request_id, approver)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read INTEGER NOT NULL DEFAULT 0
        )
    """)
    init_chain(conn)

    c.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                  ("admin", generate_password_hash("admin123"), "admin"))
        append_block(conn, "USER_CREATED", {"username": "admin", "role": "admin", "reason": "bootstrap"})
    conn.commit()
    conn.close()

def broadcast(conn, message: str):
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    for row in c.fetchall():
        c.execute("INSERT INTO notifications (recipient, message, created_at) VALUES (?,?,?)",
                  (row["username"], message, datetime.utcnow().isoformat()))
    conn.commit()

def get_user(username: str):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row

def list_files_for(user: str):
    conn = db_conn()
    c = conn.cursor()
    if session.get("role") in ["admin", "staff"]:
        c.execute("SELECT * FROM files ORDER BY uploaded_at DESC")
    else:
        c.execute("SELECT * FROM files WHERE owner = ? ORDER BY uploaded_at DESC", (user,))
    rows = c.fetchall()
    conn.close()
    return rows

def list_recent_requests(limit: int = 5):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM requests ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def list_pending_requests():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM requests WHERE status = 'pending' ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def current_user_can_approve() -> bool:
    return session.get("role") in APPROVER_ROLES

# --- Approval Logic ---
def finalize_if_ready(req_id: int):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM requests WHERE id=?", (req_id,))
    req = c.fetchone()
    if not req:
        conn.close()
        return

    requester = req["requester"]

    # Check for any rejections
    c.execute("SELECT COUNT(*) FROM request_decisions WHERE request_id = ? AND decision='reject'", (req_id,))
    if c.fetchone()[0] > 0:
        c.execute("UPDATE requests SET status='rejected' WHERE id=?", (req_id,))
        append_block(conn, "REQUEST_REJECTED", {"request_id": req_id})
        broadcast(conn, f"Request #{req_id} rejected.")
        
        # [FIX 1] Clean up the storage leak for rejected uploads
        if req["action"] == "upload":
            sidecar = os.path.join(STORAGE_DIR, f".pending_{req_id}.json")
            if os.path.exists(sidecar):
                try:
                    with open(sidecar, "r", encoding="utf-8") as fp:
                        meta = json.load(fp)
                    stored_file = os.path.join(STORAGE_DIR, meta.get("stored", ""))
                    if os.path.exists(stored_file):
                        os.remove(stored_file)
                    os.remove(sidecar)
                except Exception:
                    pass
        conn.commit()
        conn.close()
        return

    # [FIX 2] Calculate Quorum securely but allow Admins to pass
    c.execute("SELECT role FROM users WHERE username=?", (requester,))
    user_row = c.fetchone()
    req_role = user_row["role"] if user_row else "user"

    c.execute("SELECT COUNT(*) FROM users WHERE role IN ('staff','admin') AND username != ?", (requester,))
    max_approvers = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM request_decisions WHERE request_id = ? AND decision='approve' AND approver != ?", (req_id, requester))
    approvals = c.fetchone()[0]

    # If an Admin made the request, include their own self-approval
    if req_role == "admin":
        c.execute("SELECT COUNT(*) FROM request_decisions WHERE request_id = ? AND decision='approve' AND approver = ?", (req_id, requester))
        if c.fetchone()[0] > 0:
            approvals += 1
        max_approvers = max(1, max_approvers) # Ensure quorum is possible for sole admin

    quorum = min(APPROVAL_QUORUM, max_approvers) if max_approvers > 0 else 1

    if approvals >= quorum:
        c.execute("UPDATE requests SET status='approved' WHERE id=?", (req_id,))
        append_block(conn, "REQUEST_APPROVED", {"request_id": req_id, "approvals": approvals, "quorum": quorum})
        broadcast(conn, f"Request #{req_id} approved (quorum {approvals}/{quorum}).")
    
    conn.commit()
    conn.close()

@app.context_processor
def inject_globals():
    csrf_token()
    return dict(csrf_token=csrf_token, current_user=session.get("user"), current_role=session.get("role"), quorum=APPROVAL_QUORUM)

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user"] = user["username"]
            session["role"] = user["role"]
            csrf_token()
            append_block(db_conn(), "LOGIN", {"username": user["username"]})
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "bad")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    require_csrf()
    username = request.form.get("reg_username", "").strip()
    password = request.form.get("reg_password", "")
    role = "user" # Forced secure role assignment
    
    if not username or not password:
        flash("Username and password required.", "bad")
        return redirect(url_for("login"))
        
    conn = db_conn()
    try:
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                     (username, generate_password_hash(password), role))
        append_block(conn, "USER_CREATED", {"username": username, "role": role, "reason": "self-register"})
        conn.commit()
        flash("Registered. You can login now.", "ok")
    except sqlite3.IntegrityError:
        flash("Username already exists.", "bad")
    finally:
        conn.close()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    files = list_files_for(session["user"])
    pending = list_pending_requests() if current_user_can_approve() else []
    recent = list_recent_requests(limit=10)
    return render_template("dashboard.html", files=files, pending=pending, recent_reqs=recent)

@app.route("/request/upload", methods=["POST"])
@login_required
def request_upload():
    require_csrf()
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choose a file first.", "bad")
        return redirect(url_for("dashboard"))

    filename = secure_filename(f.filename)
    data = f.read()
    if not data:
        flash("Empty file not allowed.", "bad")
        return redirect(url_for("dashboard"))

    digest = sha256_bytes(data)
    stored = f"{secrets.token_hex(16)}_{filename}"
    path = os.path.join(STORAGE_DIR, stored)
    with open(path, "wb") as out:
        out.write(data)

    conn = db_conn()
    c = conn.cursor()
    c.execute("INSERT INTO requests (requester, action, orig_filename, mimetype, sha256, status, created_at) VALUES (?,?,?,?,?,?,?)",
              (session["user"], "upload", filename, f.mimetype, digest, "pending", datetime.utcnow().isoformat()))
    req_id = c.lastrowid

    append_block(conn, "REQUEST_CREATED", {"request_id": req_id, "action": "upload", "requester": session["user"], "filename": filename, "sha256": digest})
    broadcast(conn, f"New upload request #{req_id} by {session['user']}.")

    sidecar = os.path.join(STORAGE_DIR, f".pending_{req_id}.json")
    with open(sidecar, "w", encoding="utf-8") as fp:
        json.dump({"stored": stored, "orig": filename, "sha256": digest}, fp)

    conn.commit()
    conn.close()
    flash(f"Upload request #{req_id} created. Waiting for approvals.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/request/download/<int:file_id>", methods=["POST"])
@login_required
def request_download(file_id: int):
    require_csrf()
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id=?", (file_id,))
    file_row = c.fetchone()
    if not file_row:
        conn.close()
        flash("File not found.", "bad")
        return redirect(url_for("dashboard"))

    c.execute("INSERT INTO requests (requester, action, file_id, orig_filename, mimetype, sha256, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
              (session["user"], "download", file_id, file_row["orig_filename"], file_row["mimetype"], file_row["sha256"], "pending", datetime.utcnow().isoformat()))
    req_id = c.lastrowid

    append_block(conn, "REQUEST_CREATED", {"request_id": req_id, "action": "download", "requester": session["user"], "file_id": file_id, "sha256": file_row["sha256"]})
    broadcast(conn, f"New download request #{req_id} by {session['user']} for file {file_row['orig_filename']}.")
    conn.commit()
    conn.close()
    flash(f"Download request #{req_id} created. Waiting for approvals.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/requests")
@login_required
def requests_page():
    conn = db_conn()
    c = conn.cursor()
    approver = current_user_can_approve()
    pending = []
    info = {}
    
    if approver:
        c.execute("SELECT * FROM requests WHERE status = 'pending' ORDER BY created_at DESC")
        pending = c.fetchall()
        for r in pending:
            rid = r["id"]
            c.execute("SELECT COUNT(*) FROM request_decisions WHERE request_id=? AND decision='approve'", (rid,))
            approvals = c.fetchone()[0]
            c.execute("SELECT decision FROM request_decisions WHERE request_id=? AND approver=?", (rid, session["user"]))
            d = c.fetchone()
            info[rid] = {"approvals": approvals, "my_decision": (d["decision"] if d else None)}

    c.execute("SELECT * FROM requests WHERE requester=? ORDER BY created_at DESC", (session["user"],))
    my_reqs = c.fetchall()
    conn.close()
    return render_template("requests.html", requests=pending, info=info, my_reqs=my_reqs, approver=approver)

@app.route("/decision", methods=["POST"])
@login_required
def decision():
    require_csrf()
    if not current_user_can_approve():
        flash("Only staff/admin can approve requests.", "bad")
        return redirect(url_for("dashboard"))

    try:
        req_id = int(request.form.get("request_id", "0"))
    except ValueError:
        flash("Invalid request ID.", "bad")
        return redirect(url_for("requests_page"))

    decision_value = request.form.get("decision")
    if decision_value not in {"approve", "reject"}:
        flash("Invalid decision.", "bad")
        return redirect(url_for("requests_page"))

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM requests WHERE id=?", (req_id,))
    req = c.fetchone()
    
    if not req:
        conn.close()
        flash("Request not found.", "bad")
        return redirect(url_for("requests_page"))

    # [FIX 2] Prevent Staff from self-approving, but allow Admins
    if req["requester"] == session["user"] and session["role"] != "admin":
        conn.close()
        flash("Requester cannot approve or reject their own request.", "bad")
        return redirect(url_for("requests_page"))

    try:
        c.execute("INSERT INTO request_decisions (request_id, approver, decision, decided_at) VALUES (?,?,?,?)",
                  (req_id, session["user"], decision_value, datetime.utcnow().isoformat()))
        append_block(conn, "DECISION", {"request_id": req_id, "approver": session["user"], "decision": decision_value})
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        flash("You already decided on this request.", "bad")
        return redirect(url_for("requests_page"))

    conn.close()
    finalize_if_ready(req_id)

    # Materialise file record for approved uploads
    conn2 = db_conn()
    c2 = conn2.cursor()
    c2.execute("SELECT * FROM requests WHERE id=?", (req_id,))
    req2 = c2.fetchone()

    if req2 and req2["action"] == "upload" and req2["status"] == "approved":
        c2.execute("SELECT COUNT(*) FROM files WHERE sha256=? AND owner=? AND orig_filename=?",
                   (req2["sha256"], req2["requester"], req2["orig_filename"]))
        if c2.fetchone()[0] == 0:
            sidecar = os.path.join(STORAGE_DIR, f".pending_{req_id}.json")
            meta = None
            if os.path.exists(sidecar):
                try:
                    with open(sidecar, "r", encoding="utf-8") as fp:
                        meta = json.load(fp)
                except Exception:
                    meta = None

            if meta and "stored" in meta:
                c2.execute("INSERT INTO files (owner, orig_filename, stored_filename, mimetype, sha256, uploaded_at) VALUES (?,?,?,?,?,?)",
                           (req2["requester"], req2["orig_filename"], meta["stored"], req2["mimetype"], req2["sha256"], datetime.utcnow().isoformat()))
                file_id = c2.lastrowid
                append_block(conn2, "FILE_STORED", {"file_id": file_id, "owner": req2["requester"], "filename": req2["orig_filename"], "sha256": req2["sha256"]})
                conn2.commit()
                try:
                    os.remove(sidecar)
                except OSError:
                    pass
    conn2.close()
    flash("Decision saved.", "ok")
    return redirect(url_for("requests_page"))

@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id: int):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id=?", (file_id,))
    f = c.fetchone()
    
    if not f:
        conn.close()
        flash("File not found.", "bad")
        return redirect(url_for("dashboard"))

    # Staff/Admin can directly download without needing an approved request
    if session.get("role") in ["admin", "staff"]:
        append_block(conn, "DOWNLOAD_DIRECT", {"file_id": file_id, "by": session["user"], "role": session.get("role")})
        conn.close()
        return send_from_directory(
            STORAGE_DIR,
            f["stored_filename"],
            as_attachment=True,
            download_name=f["orig_filename"],
            mimetype=f["mimetype"] or "application/octet-stream"
        )

    # [FIX 3] Strict single-use policy: check for an 'approved' request
    c.execute("SELECT id FROM requests WHERE requester=? AND action='download' AND file_id=? AND status='approved' LIMIT 1",
              (session["user"], file_id))
    req_row = c.fetchone()
    
    if not req_row:
        conn.close()
        flash("Download not allowed. You need an approved, unused download request.", "bad")
        return redirect(url_for("dashboard"))

    # Mark the request as 'completed' so it cannot be used again
    req_id = req_row["id"]
    c.execute("UPDATE requests SET status='completed' WHERE id=?", (req_id,))
    conn.commit()
    
    append_block(conn, "DOWNLOAD", {"file_id": file_id, "by": session["user"], "request_id": req_id})
    conn.close()

    return send_from_directory(
        STORAGE_DIR,
        f["stored_filename"],
        as_attachment=True,
        download_name=f["orig_filename"],
        mimetype=f["mimetype"] or "application/octet-stream"
    )

# ... (notifications, admin_users, admin_chain, chain_public, status, logout remain exactly the same) ...

@app.route("/notifications")
@login_required
def notifications():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM notifications WHERE recipient=? ORDER BY created_at DESC LIMIT 200", (session["user"],))
    notes = c.fetchall()
    conn.close()
    return render_template("notifications.html", notes=notes)

@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_users():
    conn = db_conn()
    c = conn.cursor()
    
    if request.method == "POST":
        require_csrf()
        action = request.form.get("action")
        target_user = request.form.get("username", "").strip()
        
        if action == "delete":
            if target_user == session["user"]:
                flash("Cannot delete yourself.", "bad")
            else:
                c.execute("DELETE FROM users WHERE username=?", (target_user,))
                append_block(conn, "USER_DELETED", {"username": target_user, "by": session["user"]})
                conn.commit()
                flash(f"User {target_user} deleted.", "ok")
                
        elif action == "create":
            password = request.form.get("password", "")
            role = request.form.get("role", "user")
            if role not in ALLOWED_ROLES:
                role = "user"
            if not target_user or not password:
                flash("Username and password required.", "bad")
            else:
                try:
                    c.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                              (target_user, generate_password_hash(password), role))
                    append_block(conn, "USER_CREATED", {"username": target_user, "role": role, "by": session["user"]})
                    conn.commit()
                    flash(f"User {target_user} created with role {role}.", "ok")
                except sqlite3.IntegrityError:
                    flash("Username already exists.", "bad")
                    
        return redirect(url_for("admin_users"))
        
    c.execute("SELECT id, username, role FROM users ORDER BY id ASC")
    users = c.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

@app.route("/admin/chain")
@login_required
@role_required("admin")
def admin_chain():
    conn = db_conn()
    ok, msg = verify_chain(conn)
    c = conn.cursor()
    c.execute("SELECT * FROM chain_blocks ORDER BY idx DESC")
    blocks = c.fetchall()
    conn.close()
    return render_template("chain-admin.html", blocks=blocks, ok=ok, msg=msg)

@app.route("/chain")
@login_required
def chain_public():
    conn = db_conn()
    ok, msg = verify_chain(conn)
    c = conn.cursor()
    c.execute("SELECT * FROM chain_blocks ORDER BY idx DESC LIMIT 100")
    blocks = c.fetchall()
    conn.close()
    return render_template("chain.html", blocks=blocks, ok=ok, msg=msg)

@app.route("/status")
@login_required
def status():
    conn = db_conn()
    c = conn.cursor()
    
    stats = {
        "quorum": APPROVAL_QUORUM,
        "max_upload_mb": MAX_UPLOAD_MB
    }
    
    c.execute("SELECT COUNT(*) FROM users")
    stats["users"] = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM files")
    stats["files"] = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM requests WHERE status='pending'")
    stats["pending_reqs"] = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM requests WHERE status='approved'")
    stats["approved_reqs"] = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM requests WHERE status='rejected'")
    stats["rejected_reqs"] = c.fetchone()[0]
    
    ok, msg = verify_chain(conn)
    stats["chain_ok"] = ok
    stats["chain_msg"] = msg
    
    conn.close()
    return render_template("status.html", stats=stats)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# Initialise DB on every startup (works with both Gunicorn and direct run)
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)