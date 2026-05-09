from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from pymongo import MongoClient
from bson.objectid import ObjectId
from functools import wraps
import os

# Use the directory where app.py lives — works no matter which folder you run from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# ── MongoDB ──────────────────────────────────────────────────────────────────
client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))
db = client["secure_web_app"]
users_col = db["users"]
notes_col = db["notes"]

# Ensure unique index on username
users_col.create_index("username", unique=True)

# ── Fernet Encryption ────────────────────────────────────────────────────────
FERNET_KEY = os.environ.get("FERNET_KEY", "").encode()
if not FERNET_KEY:
    # Generate a key at startup (in production, persist this key securely)
    FERNET_KEY = Fernet.generate_key()
    print(f"[WARNING] Generated a temporary Fernet key. Set FERNET_KEY env var for persistence.")

cipher = Fernet(FERNET_KEY)


def encrypt_data(plaintext: str) -> str:
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str) -> str:
    try:
        return cipher.decrypt(ciphertext.encode()).decode()
    except Exception:
        return "[Decryption Error]"


# ── Auth Helpers ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in.", "warning")
            return redirect(url_for("login"))
        user = users_col.find_one({"_id": ObjectId(session["user_id"])})
        if not user or user.get("role") != "admin":
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    if "user_id" in session:
        return users_col.find_one({"_id": ObjectId(session["user_id"])})
    return None


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    user = get_current_user()
    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Input validation
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")
        if len(username) < 3 or len(username) > 32:
            flash("Username must be between 3 and 32 characters.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        hashed = generate_password_hash(password)
        try:
            result = users_col.insert_one({
                "username": username,
                "password_hash": hashed,
                "role": "user"
            })
            session["user_id"]   = str(result.inserted_id)
            session["username"]  = username
            session["role"]      = "user"
            flash("Account created successfully! Welcome.", "success")
            return redirect(url_for("dashboard"))
        except Exception:
            flash("Username already exists.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Both fields are required.", "error")
            return render_template("login.html")

        user = users_col.find_one({"username": username})
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"]  = str(user["_id"])
            session["username"] = user["username"]
            session["role"]     = user["role"]
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    # Fetch this user's notes and decrypt them
    raw_notes = list(notes_col.find({"user_id": session["user_id"]}))
    notes = []
    for n in raw_notes:
        notes.append({
            "id": str(n["_id"]),
            "title": n.get("title", ""),
            "content": decrypt_data(n["content_enc"])
        })
    return render_template("dashboard.html", user=user, notes=notes)


@app.route("/notes/add", methods=["POST"])
@login_required
def add_note():
    title   = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if not title or not content:
        flash("Title and content are required.", "error")
        return redirect(url_for("dashboard"))
    if len(title) > 100:
        flash("Title must be under 100 characters.", "error")
        return redirect(url_for("dashboard"))
    if len(content) > 2000:
        flash("Note content must be under 2000 characters.", "error")
        return redirect(url_for("dashboard"))

    encrypted = encrypt_data(content)
    notes_col.insert_one({
        "user_id": session["user_id"],
        "title": title,
        "content_enc": encrypted
    })
    flash("Note saved and encrypted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/notes/delete/<note_id>", methods=["POST"])
@login_required
def delete_note(note_id):
    notes_col.delete_one({"_id": ObjectId(note_id), "user_id": session["user_id"]})
    flash("Note deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/admin")
@admin_required
def admin_panel():
    user  = get_current_user()
    users = list(users_col.find({}, {"password_hash": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
    total_notes = notes_col.count_documents({})
    return render_template("admin.html", user=user, users=users, total_notes=total_notes)


@app.route("/admin/promote/<user_id>", methods=["POST"])
@admin_required
def promote_user(user_id):
    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": "admin"}})
    flash("User promoted to admin.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/demote/<user_id>", methods=["POST"])
@admin_required
def demote_user(user_id):
    # Don't allow demoting yourself
    if user_id == session["user_id"]:
        flash("You cannot demote yourself.", "error")
        return redirect(url_for("admin_panel"))
    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": "user"}})
    flash("User demoted to regular user.", "info")
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_user/<user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot delete your own account here.", "error")
        return redirect(url_for("admin_panel"))
    users_col.delete_one({"_id": ObjectId(user_id)})
    notes_col.delete_many({"user_id": user_id})
    flash("User and their notes deleted.", "info")
    return redirect(url_for("admin_panel"))


# ── Error Handlers ───────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


if __name__ == "__main__":
    app.run(debug=True)
    