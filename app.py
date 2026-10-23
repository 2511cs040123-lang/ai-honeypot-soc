from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from pathlib import Path
import sqlite3, json, hashlib, datetime, random, os, re
from werkzeug.security import generate_password_hash, check_password_hash

ROOT = Path(__file__).resolve().parent
DB = ROOT / "data" / "honeypot.db"
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SENTINEL_SECRET_KEY", "local-demo-change-this-secret")
(ROOT / "templates").mkdir(exist_ok=True)
(ROOT / "data").mkdir(exist_ok=True)

def connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, source_ip TEXT NOT NULL,
            stage TEXT NOT NULL, event_type TEXT NOT NULL,
            severity TEXT NOT NULL, details TEXT NOT NULL,
            action TEXT NOT NULL, previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS blocked_ips(
            ip TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at TEXT NOT NULL
        )""")
        if con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0:
            seed_events(con)

def chain_hash(payload, previous_hash):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")) + previous_hash
    return hashlib.sha256(raw.encode()).hexdigest()

def add_event(con, ip, stage, event_type, severity, details, action):
    prev = con.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = prev["event_hash"] if prev else "GENESIS"
    ts = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    payload = {"timestamp": ts, "source_ip": ip, "stage": stage, "event_type": event_type,
               "severity": severity, "details": details, "action": action}
    digest = chain_hash(payload, previous_hash)
    con.execute("""INSERT INTO events(timestamp,source_ip,stage,event_type,severity,details,action,previous_hash,event_hash)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (ts, ip, stage, event_type, severity, details, action, previous_hash, digest))

def seed_events(con):
    samples = [
        ("192.0.2.41","Reconnaissance","Port scan","Medium","Repeated connection probes","Monitored"),
        ("198.51.100.23","Initial Access","SSH login guessing","High","14 failed login attempts","Rate limited"),
        ("203.0.113.17","Discovery","Sensitive path probe","High","Requested /admin-backup","Decoy served"),
        ("198.51.100.88","Credential Access","Fake credential attempt","Critical","Submitted honeypot-only username","Blocked"),
        ("192.0.2.77","Lateral Movement","Service enumeration","Medium","Attempted access to decoy service","Monitored"),
    ]
    for row in samples:
        add_event(con, *row)
    con.commit()

init_db()

MODULES = [
    {"n":1,"name":"Live Security Dashboard","desc":"Live event feed, risk counts, and system status."},
    {"n":2,"name":"AI Threat Analysis","desc":"Explainable rule-based risk scoring and attack-stage classification."},
    {"n":3,"name":"Dynamic Honeypot Simulator","desc":"Generate safe, simulated attacker behavior against decoy services."},
    {"n":4,"name":"Automated IP Blocking","desc":"Add simulated source IPs to a local blocklist and record response actions."},
    {"n":5,"name":"Blockchain Forensic Ledger","desc":"Hash-linked, tamper-evident event records with chain verification."},
    {"n":6,"name":"Forensic Reports","desc":"Filter events and export a JSON incident report."},
]

def classify(details, event_type):
    t = (details + " " + event_type).lower()
    if any(x in t for x in ["credential", "password", "login", "ssh"]):
        return "Credential Access", "Critical" if any(x in t for x in ["credential", "password"]) else "High", 90
    if any(x in t for x in ["admin", "backup", "path", "directory"]):
        return "Discovery", "High", 75
    if any(x in t for x in ["scan", "probe", "port"]):
        return "Reconnaissance", "Medium", 55
    if any(x in t for x in ["service", "lateral"]):
        return "Lateral Movement", "High", 72
    return "Initial Access", "Medium", 50

def login_required():
    return "user_id" in session

@app.get("/")
def home():
    if not login_required():
        return redirect(url_for("login"))
    return render_template("index.html", modules=MODULES, current_user=session.get("full_name", "User"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not full_name or not username or not email or not password:
            flash("Please fill in every field.", "error")
        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash("Username must be 3–30 characters using letters, numbers, dots, underscores or hyphens.", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
            try:
                with connect() as con:
                    con.execute("INSERT INTO users(full_name,username,email,password_hash,created_at) VALUES(?,?,?,?,?)",
                                (full_name, username, email, generate_password_hash(password), now))
                flash("Account created. Sign in with your new credentials.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "error")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if login_required():
        return redirect(url_for("home"))
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        with connect() as con:
            user = con.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE",
                               (identity, identity)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]
            session["username"] = user["username"]
            return redirect(url_for("home"))
        flash("Invalid username/email or password.", "error")
    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.before_request
def require_login_for_workspace():
    if request.path.startswith("/api/") and "user_id" not in session:
        return jsonify({"error":"Please sign in to access the workspace."}), 401

@app.get("/api/summary")
def summary():
    with connect() as con:
        events = con.execute("SELECT * FROM events ORDER BY id DESC").fetchall()
        blocked = con.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    return jsonify({"total":len(events), "critical":sum(e["severity"]=="Critical" for e in events),
                    "high":sum(e["severity"]=="High" for e in events), "blocked":blocked,
                    "events":[dict(e) for e in events[:12]]})

@app.get("/api/events")
def get_events():
    with connect() as con:
        rows = con.execute("SELECT * FROM events ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/simulate")
def simulate():
    body = request.get_json(silent=True) or {}
    scenario = body.get("scenario", "credential")
    ip = body.get("ip", "").strip() or random.choice(["192.0.2.150","198.51.100.42","203.0.113.9"])
    # Documentation-only IP ranges are used intentionally; no real traffic is sent.
    scenarios = {
        "recon": ("Port scan", "Multiple ports probed in a short interval"),
        "path": ("Sensitive path probe", "Requested /admin-backup and /.env decoy paths"),
        "credential": ("SSH login guessing", "Repeated failed login attempts against fake SSH banner"),
        "lateral": ("Service enumeration", "Attempted to enumerate simulated internal decoy services"),
        "exfil": ("Data exfiltration attempt", "Large download request against synthetic decoy data"),
    }
    event_type, details = scenarios.get(scenario, scenarios["credential"])
    stage, severity, score = classify(details, event_type)
    action = "Blocked" if score >= 85 else ("Decoy served" if score >= 70 else "Monitored")
    with connect() as con:
        exists = con.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
        if exists:
            action = "Blocked (already on blocklist)"
        add_event(con, ip, stage, event_type, severity, f"{details}. Risk score: {score}/100.", action)
        con.commit()
        latest = dict(con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1").fetchone())
    return jsonify({"event":latest, "risk_score":score, "explanation":f"Rule-based score {score}/100 because the event matched the {stage.lower()} detection pattern. This is a demo classifier, not a trained AI model."})

@app.post("/api/block")
def block_ip():
    body = request.get_json(silent=True) or {}
    ip = body.get("ip", "").strip()
    reason = body.get("reason", "Repeated suspicious activity").strip()
    if not ip or len(ip) > 64 or any(c in ip for c in " \t\r\n"):
        return jsonify({"error":"Enter a valid-looking IP address without spaces."}), 400
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    with connect() as con:
        con.execute("INSERT OR IGNORE INTO blocked_ips(ip,reason,created_at) VALUES(?,?,?)", (ip,reason,now))
        add_event(con, ip, "Response", "Blocklist update", "High", reason, "Blocked")
        con.commit()
    return jsonify({"ok":True,"ip":ip})

@app.get("/api/blocked")
def blocked():
    with connect() as con:
        rows = con.execute("SELECT * FROM blocked_ips ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/verify")
def verify():
    with connect() as con:
        rows = con.execute("SELECT * FROM events ORDER BY id").fetchall()
    expected = "GENESIS"
    bad = []
    for r in rows:
        payload = {"timestamp":r["timestamp"],"source_ip":r["source_ip"],"stage":r["stage"],
                   "event_type":r["event_type"],"severity":r["severity"],"details":r["details"],"action":r["action"]}
        digest = chain_hash(payload, expected)
        if r["previous_hash"] != expected or r["event_hash"] != digest:
            bad.append(r["id"])
        expected = r["event_hash"]
    return jsonify({"valid":not bad,"checked":len(rows),"tampered_ids":bad,
                    "note":"Hash-linked tamper-evidence demo. This is not a distributed blockchain network."})

@app.get("/api/report")
def report():
    with connect() as con:
        events = [dict(r) for r in con.execute("SELECT * FROM events ORDER BY id DESC").fetchall()]
        blocks = [dict(r) for r in con.execute("SELECT * FROM blocked_ips ORDER BY created_at DESC").fetchall()]
    return jsonify({"generated_at":datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                    "project":"AI-Driven Honeypot for Dynamic Multistage Attack Prevention with Blockchain Forensic Method",
                    "events":events,"blocked_ips":blocks})

if __name__ == "__main__":
app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=False)
