import os, sqlite3, hashlib, secrets, json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, send_from_directory, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = DATA_DIR / "certificates.db"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "webp"}
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "12"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db_conn():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','institution','student','verifier')),
      organization TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS certificates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      certificate_id TEXT NOT NULL UNIQUE,
      student_name TEXT NOT NULL,
      student_number TEXT DEFAULT '',
      course TEXT NOT NULL,
      grade TEXT DEFAULT '',
      institution_id INTEGER NOT NULL,
      issued_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','revoked')),
      file_name TEXT DEFAULT '',
      file_sha256 TEXT DEFAULT '',
      record_sha256 TEXT NOT NULL,
      previous_hash TEXT NOT NULL DEFAULT 'GENESIS',
      record_hash TEXT NOT NULL,
      revoked_at TEXT DEFAULT '',
      revoked_reason TEXT DEFAULT '',
      FOREIGN KEY(institution_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER,
      action TEXT NOT NULL,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(actor_id) REFERENCES users(id)
    );
    """)
    # Seed demo admin only if there are no users. Change the password immediately.
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        conn.execute(
          "INSERT INTO users(name,email,password_hash,role,organization,created_at) VALUES(?,?,?,?,?,?)",
          ("System Administrator", "admin@example.com", generate_password_hash("Admin123!ChangeMe"),
           "admin", "Certificate Validation System", now_iso())
        )
    conn.commit()
    conn.close()

def audit(actor_id, action, details):
    db_conn().execute("INSERT INTO audit_log(actor_id,action,details,created_at) VALUES(?,?,?,?)",
                      (actor_id, action, details[:1000], now_iso()))
    db_conn().commit()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db_conn().execute("SELECT id,name,email,role,organization,created_at FROM users WHERE id=?", (uid,)).fetchone()

@app.before_request
def load_user():
    g.user = current_user()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not g.user:
                flash("Please sign in to continue.", "warning")
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_record_hash(certificate_id, student_name, student_number, course, grade, institution_id, issued_at, file_sha256, previous_hash):
    payload = json.dumps({
        "certificate_id": certificate_id, "student_name": student_name, "student_number": student_number,
        "course": course, "grade": grade, "institution_id": institution_id, "issued_at": issued_at,
        "file_sha256": file_sha256, "previous_hash": previous_hash
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

@app.route("/")
def index():
    stats = {"total": 0, "valid": 0, "revoked": 0, "institutions": 0}
    conn = db_conn()
    stats["total"] = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    stats["valid"] = conn.execute("SELECT COUNT(*) FROM certificates WHERE status='valid'").fetchone()[0]
    stats["revoked"] = conn.execute("SELECT COUNT(*) FROM certificates WHERE status='revoked'").fetchone()[0]
    stats["institutions"] = conn.execute("SELECT COUNT(*) FROM users WHERE role='institution'").fetchone()[0]
    recent = conn.execute("""SELECT c.certificate_id,c.student_name,c.course,c.status,c.issued_at,u.organization
      FROM certificates c JOIN users u ON u.id=c.institution_id ORDER BY c.id DESC LIMIT 5""").fetchall()
    return render_template("index.html", stats=stats, recent=recent)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        organization = request.form.get("organization", "").strip()
        if not name or not email or len(password) < 8:
            flash("Enter your name and email, and use a password with at least 8 characters.", "danger")
            return render_template("register.html")
        if role not in {"institution", "student", "verifier"}:
            flash("Please choose a supported account type.", "danger")
            return render_template("register.html")
        if role == "institution" and not organization:
            flash("Institution name is required for institution accounts.", "danger")
            return render_template("register.html")
        try:
            db_conn().execute("""INSERT INTO users(name,email,password_hash,role,organization,created_at)
                VALUES(?,?,?,?,?,?)""", (name,email,generate_password_hash(password),role,organization,now_iso()))
            db_conn().commit()
            audit(None, "account_registered", f"{role}: {email}")
            flash("Account created. Sign in to continue. Institution accounts are demo accounts and should be verified by an administrator before production use.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("An account with this email already exists.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db_conn().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            audit(user["id"], "login", "User signed in")
            flash(f"Welcome, {user['name']}!", "success")
            dest = request.args.get("next", "")
            if dest.startswith("/") and not dest.startswith("//"):
                return redirect(dest)
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if g.user:
        audit(g.user["id"], "logout", "User signed out")
    session.clear()
    flash("You have signed out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn = db_conn()
    if g.user["role"] == "admin":
        certs = conn.execute("""SELECT c.*,u.organization FROM certificates c JOIN users u ON u.id=c.institution_id
                                ORDER BY c.id DESC LIMIT 100""").fetchall()
    elif g.user["role"] == "institution":
        certs = conn.execute("SELECT * FROM certificates WHERE institution_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
    elif g.user["role"] == "student":
        certs = conn.execute("SELECT * FROM certificates WHERE lower(student_name)=lower(?) ORDER BY id DESC", (g.user["name"],)).fetchall()
    else:
        certs = []
    return render_template("dashboard.html", certs=certs)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        organization = request.form.get("organization", "").strip()
        if not name:
            flash("Name cannot be empty.", "danger")
        else:
            db_conn().execute("UPDATE users SET name=?,organization=? WHERE id=?", (name,organization,g.user["id"]))
            db_conn().commit()
            audit(g.user["id"], "profile_updated", "Profile details updated")
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
    user = db_conn().execute("SELECT name,email,role,organization,created_at FROM users WHERE id=?", (g.user["id"],)).fetchone()
    return render_template("profile.html", profile=user)

@app.route("/issue", methods=["GET", "POST"])
@roles_required("institution", "admin")
def issue():
    if request.method == "POST":
        student_name = request.form.get("student_name", "").strip()
        student_number = request.form.get("student_number", "").strip()
        course = request.form.get("course", "").strip()
        grade = request.form.get("grade", "").strip()
        if not student_name or not course:
            flash("Student name and course are required.", "danger")
            return render_template("issue.html")
        uploaded = request.files.get("certificate_file")
        stored_name, file_hash = "", ""
        if uploaded and uploaded.filename:
            if not allowed_file(uploaded.filename):
                flash("Upload PDF, PNG, JPG, JPEG, or WEBP files only.", "danger")
                return render_template("issue.html")
            stored_name = secrets.token_hex(16) + "_" + secure_filename(uploaded.filename)
            path = UPLOAD_DIR / stored_name
            uploaded.save(path)
            file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        certificate_id = secrets.token_hex(12)
        issued_at = now_iso()
        institution_id = g.user["id"]
        conn = db_conn()
        previous = conn.execute("SELECT record_hash FROM certificates ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = previous["record_hash"] if previous else "GENESIS"
        record_hash = calculate_record_hash(certificate_id, student_name, student_number, course, grade,
                                             institution_id, issued_at, file_hash, previous_hash)
        conn.execute("""INSERT INTO certificates(certificate_id,student_name,student_number,course,grade,
          institution_id,issued_at,status,file_name,file_sha256,record_sha256,previous_hash,record_hash)
          VALUES(?,?,?,?,?,?,?,'valid',?,?,?,?,?)""",
          (certificate_id,student_name,student_number,course,grade,institution_id,issued_at,stored_name,
           file_hash,record_hash,previous_hash,record_hash))
        conn.commit()
        audit(g.user["id"], "certificate_issued", certificate_id)
        flash(f"Certificate issued successfully. Certificate ID: {certificate_id}", "success")
        return redirect(url_for("certificate_detail", certificate_id=certificate_id))
    return render_template("issue.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    cert = None
    result = None
    if request.method == "POST":
        certificate_id = request.form.get("certificate_id", "").strip()
        uploaded = request.files.get("verification_file")
        uploaded_hash = ""
        upload_error = ""

        # Optional document-based verification. The uploaded bytes are hashed in memory;
        # they are not saved or altered by this verification workflow.
        if uploaded and uploaded.filename:
            if not allowed_file(uploaded.filename):
                upload_error = "Upload PDF, PNG, JPG, JPEG, or WEBP files only."
            else:
                uploaded_bytes = uploaded.read()
                if not uploaded_bytes:
                    upload_error = "The uploaded file is empty."
                else:
                    uploaded_hash = hashlib.sha256(uploaded_bytes).hexdigest()

        if upload_error:
            result = ("danger", upload_error)
        elif not certificate_id and not uploaded_hash:
            result = ("danger", "Enter a certificate ID or upload the original certificate file.")
        else:
            conn = db_conn()
            if certificate_id:
                cert = conn.execute("""SELECT c.*,u.organization FROM certificates c JOIN users u ON u.id=c.institution_id
                                       WHERE c.certificate_id=?""", (certificate_id,)).fetchone()
            elif uploaded_hash:
                cert = conn.execute("""SELECT c.*,u.organization FROM certificates c JOIN users u ON u.id=c.institution_id
                                       WHERE c.file_sha256=? AND c.file_sha256<>'' ORDER BY c.id DESC LIMIT 1""",
                                    (uploaded_hash,)).fetchone()

            if not cert:
                result = ("danger", "No matching certificate record was found. Check the ID or upload the exact original file that was attached when the certificate was issued.")
            elif cert["status"] == "revoked":
                result = ("danger", "Certificate is REVOKED and must not be accepted.")
            elif uploaded_hash and certificate_id and uploaded_hash != cert["file_sha256"]:
                result = ("danger", "The uploaded file does not match the document stored for this certificate ID. The file may be different or modified.")
            elif uploaded_hash and not cert["file_sha256"]:
                result = ("danger", "This certificate record has no original document file stored, so document matching is unavailable. Try verifying with the certificate ID.")
            else:
                valid, reason = verify_chain()
                file_ok = True
                if cert["file_name"]:
                    path = UPLOAD_DIR / cert["file_name"]
                    file_ok = path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == cert["file_sha256"]
                if not valid:
                    result = ("danger", f"Record integrity check failed: {reason}")
                elif not file_ok:
                    result = ("danger", "The stored certificate file is missing or has changed.")
                elif uploaded_hash and uploaded_hash != cert["file_sha256"]:
                    result = ("danger", "The uploaded certificate file does not match the original file.")
                else:
                    result = ("success", "Certificate record verified. " +
                              ("The uploaded file exactly matches the stored original file. " if uploaded_hash else "") +
                              "This confirms record integrity, not the real-world identity of the holder.")
        audit(g.user["id"] if g.user else None, "certificate_verified",
              (certificate_id or "file upload") + (" (upload provided)" if uploaded_hash else ""))
    return render_template("verify.html", cert=cert, result=result)

def verify_chain():
    rows = db_conn().execute("SELECT * FROM certificates ORDER BY id ASC").fetchall()
    previous = "GENESIS"
    for row in rows:
        if row["previous_hash"] != previous:
            return False, f"Certificate record {row['certificate_id']} has an incorrect previous hash."
        expected = calculate_record_hash(row["certificate_id"], row["student_name"], row["student_number"],
            row["course"], row["grade"], row["institution_id"], row["issued_at"], row["file_sha256"], row["previous_hash"])
        if expected != row["record_sha256"] or row["record_hash"] != row["record_sha256"]:
            return False, f"Certificate record {row['certificate_id']} hash does not match."
        previous = row["record_hash"]
    return True, "All records passed the local integrity check."

@app.route("/certificate/<certificate_id>")
def certificate_detail(certificate_id):
    cert = db_conn().execute("""SELECT c.*,u.organization FROM certificates c JOIN users u ON u.id=c.institution_id
                                WHERE c.certificate_id=?""", (certificate_id,)).fetchone()
    if not cert:
        abort(404)
    # Only show full personal details to issuer/admin or the student whose name matches; public verification shows minimal data.
    if not g.user or (g.user["role"] not in {"admin","institution"} and g.user["name"].lower() != cert["student_name"].lower()):
        return render_template("public_certificate.html", cert=cert)
    return render_template("certificate.html", cert=cert)

@app.route("/certificate/<certificate_id>/file")
@login_required
def certificate_file(certificate_id):
    cert = db_conn().execute("SELECT * FROM certificates WHERE certificate_id=?", (certificate_id,)).fetchone()
    if not cert or not cert["file_name"]:
        abort(404)
    if g.user["role"] not in {"admin","institution"} and g.user["name"].lower() != cert["student_name"].lower():
        abort(403)
    return send_from_directory(UPLOAD_DIR, cert["file_name"], as_attachment=True)

@app.route("/revoke", methods=["GET", "POST"])
@roles_required("institution", "admin")
def revoke():
    if request.method == "POST":
        certificate_id = request.form.get("certificate_id", "").strip()
        reason = request.form.get("reason", "").strip()[:500]
        cert = db_conn().execute("SELECT * FROM certificates WHERE certificate_id=?", (certificate_id,)).fetchone()
        if not cert:
            flash("Certificate ID not found.", "danger")
        elif g.user["role"] != "admin" and cert["institution_id"] != g.user["id"]:
            flash("You can revoke only certificates issued by your institution.", "danger")
        elif cert["status"] == "revoked":
            flash("This certificate has already been revoked.", "warning")
        else:
            db_conn().execute("UPDATE certificates SET status='revoked',revoked_at=?,revoked_reason=? WHERE id=?",
                              (now_iso(), reason or "No reason supplied", cert["id"]))
            db_conn().commit()
            audit(g.user["id"], "certificate_revoked", f"{certificate_id}: {reason}")
            flash("Certificate revoked successfully.", "success")
            return redirect(url_for("verify", certificate_id=certificate_id))
    return render_template("revoke.html")

@app.route("/admin/users")
@roles_required("admin")
def admin_users():
    users = db_conn().execute("SELECT id,name,email,role,organization,created_at FROM users ORDER BY id DESC").fetchall()
    return render_template("admin_users.html", users=users)

@app.route("/admin/audit")
@roles_required("admin")
def admin_audit():
    logs = db_conn().execute("""SELECT a.*,u.name AS actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id
                                ORDER BY a.id DESC LIMIT 200""").fetchall()
    return render_template("audit.html", logs=logs)

@app.route("/api/chain/validate")
def api_chain_validate():
    valid, reason = verify_chain()
    return jsonify({"valid": valid, "message": reason}), (200 if valid else 409)

@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="The requested page or certificate was not found."), 404

@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, message=f"File is too large. Maximum size is {MAX_UPLOAD_MB} MB."), 413

init_db()

if __name__ == "__main__":
    # Development server only. Use a production WSGI server and HTTPS for deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG") == "1")
