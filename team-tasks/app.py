"""Team Tasks backend: Flask + SQLite. Run: python app.py"""
import hashlib, os, re, secrets, sqlite3, time
from datetime import datetime
from functools import wraps
from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH", os.path.join(BASE, "tasks.db"))
TOKEN_TTL = 12 * 3600
PRIS, STS = ("low", "med", "high"), ("todo", "doing", "done")

app = Flask(__name__, static_folder=os.path.join(BASE, "static"), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
if os.environ.get("TRUST_PROXY") == "1":  # behind Render's proxy: use the real client IP
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE NOT NULL,
  role TEXT NOT NULL CHECK(role IN('admin','emp')), pw TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, created REAL NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, title TEXT NOT NULL, pri TEXT NOT NULL,
  due TEXT NOT NULL DEFAULT '', st TEXT NOT NULL DEFAULT 'todo', created_by TEXT NOT NULL, created REAL NOT NULL,
  emp_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d is not None:
        d.close()

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    c = sqlite3.connect(DB)
    c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        c.execute("INSERT INTO users(name,role,pw) VALUES('admin','admin',?)", (generate_password_hash(pw),))
        c.commit()
        if pw == "admin123":
            print("WARNING: admin created with default password 'admin123'. Set ADMIN_PASSWORD before first run.")
    c.close()

def err(msg, code=400):
    return jsonify(error=msg), code

def auth(role=None):
    def deco(f):
        @wraps(f)
        def wrap(*a, **k):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer "):
                return err("Sign in required", 401)
            th = hashlib.sha256(h[7:].encode()).hexdigest()
            r = db().execute("SELECT u.id,u.name,u.role,t.created FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.hash=?", (th,)).fetchone()
            if not r or time.time() - r["created"] > TOKEN_TTL:
                return err("Session expired. Sign in again.", 401)
            if role and r["role"] != role:
                return err("Not allowed", 403)
            g.user, g.th = r, th
            return f(*a, **k)
        return wrap
    return deco

def body():
    return request.get_json(silent=True) or {}

def task_json(r):
    return dict(id=r["id"], title=r["title"], emp_id=r["emp_id"], emp_name=r["emp_name"], pri=r["pri"],
                due=r["due"], st=r["st"], by=r["created_by"])

TASK_SQL = "SELECT t.*, u.name AS emp_name FROM tasks t JOIN users u ON u.id=t.emp_id"

def valid_due(v):
    v = (v or "").strip()
    if not v:
        return ""
    try:
        datetime.strptime(v, "%Y-%m-%d")
        return v
    except ValueError:
        return None

# ---- login (with simple brute-force limit) ----
FAILS = {}
def limited(key):
    now = time.time()
    FAILS[key] = [t for t in FAILS.get(key, []) if now - t < 300]
    return len(FAILS[key]) >= 5

@app.post("/api/login")
def login():
    d = body()
    name, pw = str(d.get("username", "")).strip(), str(d.get("password", ""))
    key = (request.remote_addr, name.lower())
    if limited(key):
        return err("Too many attempts. Try again in a few minutes.", 429)
    u = db().execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    ok = check_password_hash(u["pw"] if u else generate_password_hash("x"), pw) and u is not None
    if not ok:
        FAILS.setdefault(key, []).append(time.time())
        return err("Wrong username or password", 401)
    tok = secrets.token_urlsafe(32)
    db().execute("DELETE FROM tokens WHERE created<?", (time.time() - TOKEN_TTL,))
    db().execute("INSERT INTO tokens(hash,created,user_id) VALUES(?,?,?)",
                 (hashlib.sha256(tok.encode()).hexdigest(), time.time(), u["id"]))
    db().commit()
    return jsonify(token=tok, user=dict(id=u["id"], name=u["name"], role=u["role"]))

@app.post("/api/logout")
@auth()
def logout():
    db().execute("DELETE FROM tokens WHERE hash=?", (g.th,)); db().commit()
    return jsonify(ok=True)

@app.get("/api/me")
@auth()
def me():
    u = g.user
    return jsonify(user=dict(id=u["id"], name=u["name"], role=u["role"]))

# ---- employees (admin) ----
@app.get("/api/employees")
@auth("admin")
def list_emps():
    rows = db().execute("SELECT id,name FROM users WHERE role='emp' ORDER BY name").fetchall()
    return jsonify(employees=[dict(r) for r in rows])

@app.post("/api/employees")
@auth("admin")
def add_emp():
    d = body()
    name, pw = str(d.get("name", "")).strip(), str(d.get("password", ""))
    if not 1 <= len(name) <= 40 or not re.fullmatch(r"[\w .-]+", name):
        return err("Name must be 1-40 letters, numbers, spaces, dots or dashes")
    if len(pw) < 6:
        return err("Password must be at least 6 characters")
    try:
        cur = db().execute("INSERT INTO users(name,role,pw) VALUES(?,?,?)", (name, "emp", generate_password_hash(pw)))
        db().commit()
    except sqlite3.IntegrityError:
        return err("That name is already taken", 409)
    return jsonify(id=cur.lastrowid, name=name), 201

@app.delete("/api/employees/<int:eid>")
@auth("admin")
def del_emp(eid):
    cur = db().execute("DELETE FROM users WHERE id=? AND role='emp'", (eid,)); db().commit()
    return jsonify(ok=True) if cur.rowcount else err("Employee not found", 404)

# ---- tasks ----
@app.get("/api/tasks")
@auth()
def list_tasks():
    if g.user["role"] == "admin":
        rows = db().execute(TASK_SQL + " ORDER BY t.created DESC").fetchall()
    else:
        rows = db().execute(TASK_SQL + " WHERE t.emp_id=? ORDER BY t.created DESC", (g.user["id"],)).fetchall()
    return jsonify(tasks=[task_json(r) for r in rows])

@app.post("/api/tasks")
@auth()
def add_task():
    d = body()
    title = str(d.get("title", "")).strip()[:200]
    pri, due = d.get("pri", "med"), valid_due(d.get("due"))
    if not title: return err("Task title is required")
    if pri not in PRIS: return err("Invalid priority")
    if due is None: return err("Due date must look like 2026-12-31")
    if g.user["role"] == "admin":
        e = db().execute("SELECT id FROM users WHERE id=? AND role='emp'", (d.get("emp_id"),)).fetchone()
        if not e: return err("Choose an employee to assign this to")
        emp_id, by = e["id"], "admin"
    else:
        emp_id, by = g.user["id"], "emp"
    cur = db().execute("INSERT INTO tasks(title,pri,due,created_by,created,emp_id) VALUES(?,?,?,?,?,?)",
                       (title, pri, due, by, time.time(), emp_id))
    db().commit()
    return jsonify(id=cur.lastrowid), 201

def owned(tid):
    r = db().execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
    if r and (g.user["role"] == "admin" or r["emp_id"] == g.user["id"]):
        return r
    return None

@app.patch("/api/tasks/<int:tid>")
@auth()
def set_status(tid):
    st = body().get("st")
    if st not in STS: return err("Invalid status")
    if not owned(tid): return err("Task not found", 404)
    db().execute("UPDATE tasks SET st=? WHERE id=?", (st, tid)); db().commit()
    return jsonify(ok=True)

@app.delete("/api/tasks/<int:tid>")
@auth()
def del_task(tid):
    r = owned(tid)
    if not r: return err("Task not found", 404)
    if g.user["role"] != "admin" and r["created_by"] != "emp":
        return err("Only the admin can delete assigned tasks", 403)
    db().execute("DELETE FROM tasks WHERE id=?", (tid,)); db().commit()
    return jsonify(ok=True)

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    if request.path.startswith("/api/"):
        r.headers["Cache-Control"] = "no-store"
    return r

@app.errorhandler(404)
def nf(_):
    return err("Not found", 404) if request.path.startswith("/api/") else send_from_directory(app.static_folder, "index.html")

@app.get("/healthz")
def healthz():
    return jsonify(ok=True)

@app.get("/")
def home():
    return send_from_directory(app.static_folder, "index.html")

init_db()
if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", 5000)))
