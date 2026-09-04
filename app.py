import os
import re
import secrets
import sqlite3
from functools import wraps
from decimal import Decimal, InvalidOperation
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
DB = os.environ.get("DATABASE_PATH", "workflow_jobs.db")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com").strip().lower()
app.config["ADMIN_EMAIL"] = ADMIN_EMAIL


def db():
    c = sqlite3.connect(DB, timeout=20)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance REAL NOT NULL DEFAULT 0,
      total_earned REAL NOT NULL DEFAULT 0,
      completed INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS jobs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      reward REAL NOT NULL CHECK(reward > 0),
      minutes INTEGER NOT NULL DEFAULT 5,
      description TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS applications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      proof TEXT NOT NULL DEFAULT '',
      reviewed_at TEXT,
      UNIQUE(user_id, job_id)
    );
    CREATE TABLE IF NOT EXISTS withdrawals(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      method TEXT NOT NULL,
      account TEXT NOT NULL,
      amount REAL NOT NULL CHECK(amount > 0),
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      reviewed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS deposits(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      method TEXT NOT NULL,
      account TEXT NOT NULL,
      amount REAL NOT NULL CHECK(amount > 0),
      reference TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      reviewed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS ledger(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    if c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0:
        c.executemany("INSERT INTO jobs(title,category,reward,minutes,description) VALUES(?,?,?,?,?)", [
            ("Website Feedback", "Review", 2.50, 5, "Visit a website and submit useful feedback about the user experience."),
            ("Data Entry Task", "Data Entry", 4.00, 10, "Enter provided information into the supplied form accurately."),
            ("Social Research", "Research", 3.25, 8, "Complete a short research task and submit the requested result.")
        ])
    c.commit(); c.close()


def is_admin_user(user):
    return bool(user and user["email"].lower() == ADMIN_EMAIL)


def current_user():
    uid = session.get("uid")
    if not uid: return None
    c = db(); u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone(); c.close()
    return u


def csrf_token():
    if "csrf" not in session: session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def valid_csrf():
    return secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", ""))


def captcha_new():
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    session["captcha_answer"] = str(a + b)
    session["captcha_question"] = f"{a} + {b} = ?"


def captcha_ok(value):
    ok = secrets.compare_digest(str(value or "").strip(), str(session.get("captcha_answer", "")))
    if ok:
        session.pop("captcha_answer", None); session.pop("captcha_question", None)
    return ok


def money(value):
    try: return Decimal(str(value)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError, TypeError): return None


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        u = current_user()
        if not is_admin_user(u): abort(403)
        return f(*a, **k)
    return w


@app.context_processor
def common():
    return {"user": current_user(), "csrf": csrf_token()}


@app.before_request
def visitor_captcha_gate():
    allowed = {"static", "captcha_gate", "login", "register"}
    if request.endpoint in allowed or request.path.startswith("/static/"):
        return
    if not session.get("site_verified"):
        captcha_new()
        return redirect(url_for("captcha_gate", next=request.full_path))


@app.route("/captcha", methods=["GET", "POST"])
def captcha_gate():
    if request.method == "GET" and "captcha_answer" not in session: captcha_new()
    if request.method == "POST":
        if not valid_csrf() or not captcha_ok(request.form.get("captcha")):
            flash("Captcha is incorrect. Please try again.", "error"); captcha_new()
        else:
            session["site_verified"] = True
            return redirect(request.args.get("next") or url_for("home"))
    return render_template("captcha.html", question=session.get("captcha_question", ""), next=request.args.get("next", ""))


@app.route("/")
def home():
    c=db(); jobs=c.execute("SELECT * FROM jobs WHERE status='open' ORDER BY id DESC").fetchall(); c.close()
    return render_template("home.html", jobs=jobs)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        if not valid_csrf() or not captcha_ok(request.form.get("captcha")):
            flash("Please complete the captcha correctly.", "error"); captcha_new(); return render_template("auth.html", mode="register")
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password)<8:
            flash("Enter a valid name/email and a password of at least 8 characters.","error"); captcha_new()
        else:
            try:
                c=db(); c.execute("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)",(name,email,generate_password_hash(password))); c.commit()
                uid=c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()["id"]; c.close(); session.clear(); session["uid"]=uid; session["site_verified"]=True; csrf_token(); return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError: flash("Email already registered.","error"); captcha_new()
    if "captcha_answer" not in session: captcha_new()
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not valid_csrf() or not captcha_ok(request.form.get("captcha")):
            flash("Please complete the captcha correctly.", "error"); captcha_new(); return render_template("auth.html", mode="login")
        email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        c=db(); u=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); c.close()
        if u and check_password_hash(u["password_hash"], password):
            session.clear(); session["uid"]=u["id"]; session["site_verified"]=True; csrf_token(); return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid email or password.","error"); captcha_new()
    if "captcha_answer" not in session: captcha_new()
    return render_template("auth.html", mode="login")


@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    c=db(); uid=session["uid"]
    apps=c.execute("SELECT a.*,j.title,j.reward,j.category FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.user_id=? ORDER BY a.id DESC",(uid,)).fetchall()
    c.close(); return render_template("dashboard.html", apps=apps)


@app.route("/jobs")
def jobs():
    q=request.args.get("q","").strip(); c=db()
    rows=c.execute("SELECT * FROM jobs WHERE status='open' AND (title LIKE ? OR category LIKE ?) ORDER BY id DESC",(f"%{q}%",f"%{q}%")).fetchall(); c.close()
    return render_template("jobs.html",jobs=rows,q=q)


@app.route("/jobs/<int:job_id>")
def job(job_id):
    c=db(); j=c.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone(); c.close()
    if not j: return "Job not found",404
    return render_template("job.html",job=j)


@app.post("/jobs/<int:job_id>/apply")
@login_required
def apply(job_id):
    if not valid_csrf(): abort(400)
    c=db(); j=c.execute("SELECT id FROM jobs WHERE id=? AND status='open'",(job_id,)).fetchone()
    if not j: c.close(); flash("Job is not available.","error"); return redirect(url_for("jobs"))
    try: c.execute("INSERT INTO applications(user_id,job_id) VALUES(?,?)",(session["uid"],job_id)); c.commit(); flash("Job added to My Jobs.","success")
    except sqlite3.IntegrityError: flash("You already applied to this job.","error")
    c.close(); return redirect(url_for("dashboard"))


@app.post("/applications/<int:app_id>/submit")
@login_required
def submit(app_id):
    if not valid_csrf(): abort(400)
    proof=request.form.get("proof","").strip();
    if not proof or len(proof)>5000: flash("Please submit valid proof (max 5000 characters).","error"); return redirect(url_for("dashboard"))
    c=db(); a=c.execute("SELECT * FROM applications WHERE id=? AND user_id=?",(app_id,session["uid"])).fetchone()
    if not a: c.close(); return "Not found",404
    if a["status"] not in ("pending","rejected"): c.close(); flash("This application cannot be submitted again.","error"); return redirect(url_for("dashboard"))
    c.execute("UPDATE applications SET proof=?,status='submitted' WHERE id=?",(proof,app_id)); c.commit(); c.close(); flash("Proof submitted for admin review.","success"); return redirect(url_for("dashboard"))


@app.route("/earnings")
@login_required
def earnings():
    c=db(); u=c.execute("SELECT * FROM users WHERE id=?",(session["uid"],)).fetchone(); ledger=c.execute("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 50",(session["uid"],)).fetchall(); c.close()
    return render_template("earnings.html",u=u,ledger=ledger)


@app.route("/deposit", methods=["GET","POST"])
@login_required
def deposit():
    if request.method=="POST":
        if not valid_csrf(): abort(400)
        amount=money(request.form.get("amount")); method=request.form.get("method","").strip(); account=request.form.get("account","").strip(); reference=request.form.get("reference","").strip()
        if not amount or amount<=0 or amount>Decimal("1000000"): flash("Enter a valid deposit amount.","error")
        elif not account or len(account)>150: flash("Enter a valid payment account.","error")
        elif len(reference)>150: flash("Reference is too long.","error")
        else:
            c=db(); c.execute("INSERT INTO deposits(user_id,method,account,amount,reference) VALUES(?,?,?,?,?)",(session["uid"],method,account, float(amount),reference)); c.commit(); c.close(); flash("Deposit request submitted. Admin approval will add the balance.","success")
    c=db(); deposits=c.execute("SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC",(session["uid"],)).fetchall(); c.close()
    return render_template("deposit.html",deposits=deposits)


@app.route("/withdraw", methods=["GET","POST"])
@login_required
def withdraw():
    if request.method=="POST":
        if not valid_csrf(): abort(400)
        amount=money(request.form.get("amount")); method=request.form.get("method","").strip(); account=request.form.get("account","").strip()
        c=db(); u=c.execute("SELECT balance FROM users WHERE id=?",(session["uid"],)).fetchone()
        if not amount or amount<=0: flash("Invalid withdrawal amount.","error")
        elif not account or len(account)>150: flash("Enter a valid payment account.","error")
        elif amount > Decimal(str(u["balance"])): flash("Insufficient balance.","error")
        else:
            c.execute("INSERT INTO withdrawals(user_id,method,account,amount) VALUES(?,?,?,?)",(session["uid"],method,account,float(amount)))
            c.execute("UPDATE users SET balance=balance-? WHERE id=?",(float(amount),session["uid"]))
            c.execute("INSERT INTO ledger(user_id,type,amount,note) VALUES(?,?,?,?)",(session["uid"],"withdrawal_hold",-float(amount),"Withdrawal request pending")); c.commit(); flash("Withdrawal request submitted.","success")
        c.close()
    c=db(); ws=c.execute("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC",(session["uid"],)).fetchall(); c.close()
    return render_template("withdraw.html",withdrawals=ws)


@app.route("/admin")
@admin_required
def admin():
    c=db(); users=c.execute("SELECT * FROM users ORDER BY id DESC").fetchall(); withdrawals=c.execute("SELECT w.*,u.email,u.name FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC").fetchall(); deposits=c.execute("SELECT d.*,u.email,u.name FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.id DESC").fetchall(); applications=c.execute("SELECT a.*,u.email,u.name,j.title,j.reward FROM applications a JOIN users u ON u.id=a.user_id JOIN jobs j ON j.id=a.job_id WHERE a.status='submitted' ORDER BY a.id DESC").fetchall(); jobs=c.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall(); c.close()
    return render_template("admin.html",users=users,withdrawals=withdrawals,deposits=deposits,applications=applications,jobs=jobs)


@app.post("/admin/applications/<int:a_id>/<action>")
@admin_required
def admin_application(a_id,action):
    if not valid_csrf() or action not in ("approve","reject"): abort(400)
    c=db(); a=c.execute("SELECT * FROM applications WHERE id=?",(a_id,)).fetchone()
    if not a or a["status"]!="submitted": c.close(); return redirect(url_for("admin"))
    if action=="approve":
        j=c.execute("SELECT reward FROM jobs WHERE id=?",(a["job_id"],)).fetchone(); reward=float(j["reward"])
        c.execute("UPDATE applications SET status='approved',reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(a_id,)); c.execute("UPDATE users SET balance=balance+?,total_earned=total_earned+?,completed=completed+1 WHERE id=?",(reward,reward,a["user_id"])); c.execute("INSERT INTO ledger(user_id,type,amount,note) VALUES(?,?,?,?)",(a["user_id"],"job_earning",reward,f"Approved job #{a['job_id']}")); flash("Job approved and worker balance credited.","success")
    else:
        c.execute("UPDATE applications SET status='rejected',reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(a_id,)); flash("Job submission rejected.","success")
    c.commit(); c.close(); return redirect(url_for("admin"))


@app.post("/admin/deposits/<int:d_id>/<action>")
@admin_required
def admin_deposit(d_id,action):
    if not valid_csrf() or action not in ("approve","reject"): abort(400)
    c=db(); d=c.execute("SELECT * FROM deposits WHERE id=?",(d_id,)).fetchone()
    if d and d["status"]=="pending":
        if action=="approve":
            c.execute("UPDATE deposits SET status='approved',reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(d_id,)); c.execute("UPDATE users SET balance=balance+? WHERE id=?",(d["amount"],d["user_id"])); c.execute("INSERT INTO ledger(user_id,type,amount,note) VALUES(?,?,?,?)",(d["user_id"],"deposit",d["amount"],f"Deposit #{d_id} approved")); flash("Deposit approved and balance credited.","success")
        else: c.execute("UPDATE deposits SET status='rejected',reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(d_id,)); flash("Deposit rejected.","success")
        c.commit()
    c.close(); return redirect(url_for("admin"))


@app.post("/admin/withdrawals/<int:w_id>/<action>")
@admin_required
def admin_withdrawal(w_id,action):
    if not valid_csrf() or action not in ("approve","reject"): abort(400)
    c=db(); w=c.execute("SELECT * FROM withdrawals WHERE id=?",(w_id,)).fetchone()
    if w and w["status"]=="pending":
        status="approved" if action=="approve" else "rejected"
        c.execute("UPDATE withdrawals SET status=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(status,w_id))
        if status=="rejected":
            c.execute("UPDATE users SET balance=balance+? WHERE id=?",(w["amount"],w["user_id"])); c.execute("INSERT INTO ledger(user_id,type,amount,note) VALUES(?,?,?,?)",(w["user_id"],"withdrawal_refund",w["amount"],f"Withdrawal #{w_id} rejected/refunded"))
        else: c.execute("INSERT INTO ledger(user_id,type,amount,note) VALUES(?,?,?,?)",(w["user_id"],"withdrawal_paid",0,f"Withdrawal #{w_id} approved"))
        c.commit(); flash(f"Withdrawal {status}.","success")
    c.close(); return redirect(url_for("admin"))


@app.post("/admin/jobs/create")
@admin_required
def admin_job_create():
    if not valid_csrf(): abort(400)
    title=request.form.get("title","").strip(); category=request.form.get("category","").strip(); reward=money(request.form.get("reward")); minutes=request.form.get("minutes","5"); description=request.form.get("description","").strip()
    try: minutes=int(minutes)
    except ValueError: minutes=0
    if not title or not category or not description or not reward or reward<=0 or minutes<=0: flash("Invalid job details.","error")
    else:
        c=db(); c.execute("INSERT INTO jobs(title,category,reward,minutes,description) VALUES(?,?,?,?,?)",(title,category,float(reward),minutes,description)); c.commit(); c.close(); flash("Job created.","success")
    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(e): return "Admin access denied",403


init_db()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
