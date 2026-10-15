import os
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "documents"
DB_PATH = DATA_DIR / "docflow.db"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-THIS-TO-A-LONG-RANDOM-SECRET")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB per file

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "odt", "rtf", "txt",
    "xls", "xlsx", "ods", "csv", "ppt", "pptx",
    "png", "jpg", "jpeg", "webp"
}

def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                size INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )
        """)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("documents"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 40:
            flash("Имя пользователя должно содержать от 3 до 40 символов.", "error")
        elif len(password) < 8:
            flash("Пароль должен быть не короче 8 символов.", "error")
        else:
            try:
                with connect_db() as db:
                    db.execute(
                        "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), datetime.utcnow().isoformat())
                    )
                flash("Аккаунт создан. Теперь войдите.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Такое имя пользователя уже занято.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("documents"))
        flash("Неверное имя пользователя или пароль.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/documents")
@login_required
def documents():
    with connect_db() as db:
        docs = db.execute(
            "SELECT * FROM documents WHERE owner_id = ? ORDER BY uploaded_at DESC",
            (session["user_id"],)
        ).fetchall()
    return render_template("documents.html", docs=docs)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.getlist("files")
    if not uploaded or all(not f.filename for f in uploaded):
        flash("Выберите хотя бы один файл.", "error")
        return redirect(url_for("documents"))

    saved = 0
    for f in uploaded:
        if not f or not f.filename:
            continue
        original = secure_filename(f.filename)
        if not original or not allowed_file(original):
            flash(f"Формат файла не разрешён: {f.filename}", "error")
            continue
        stored = f"{uuid.uuid4().hex}_{original}"
        target = UPLOAD_DIR / stored
        f.save(target)
        with connect_db() as db:
            db.execute(
                """INSERT INTO documents(owner_id, original_name, stored_name, uploaded_at, size)
                   VALUES (?, ?, ?, ?, ?)""",
                (session["user_id"], original, stored, datetime.utcnow().isoformat(), target.stat().st_size)
            )
        saved += 1
    if saved:
        flash(f"Загружено файлов: {saved}. Они сохранены на сервере.", "success")
    return redirect(url_for("documents"))

@app.route("/download/<int:doc_id>")
@login_required
def download(doc_id):
    with connect_db() as db:
        doc = db.execute(
            "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
            (doc_id, session["user_id"])
        ).fetchone()
    if not doc:
        abort(404)
    return send_from_directory(UPLOAD_DIR, doc["stored_name"], as_attachment=True, download_name=doc["original_name"])

@app.route("/preview/<int:doc_id>")
@login_required
def preview(doc_id):
    with connect_db() as db:
        doc = db.execute(
            "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
            (doc_id, session["user_id"])
        ).fetchone()
    if not doc:
        abort(404)
    ext = doc["original_name"].rsplit(".", 1)[-1].lower() if "." in doc["original_name"] else ""
    if ext not in {"pdf", "png", "jpg", "jpeg", "webp", "txt"}:
        flash("Предпросмотр этого формата пока не встроен. Скачайте файл и откройте его в подходящей программе.", "error")
        return redirect(url_for("documents"))
    return send_from_directory(UPLOAD_DIR, doc["stored_name"], as_attachment=False, download_name=doc["original_name"], mimetype=None)

@app.route("/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete(doc_id):
    with connect_db() as db:
        doc = db.execute(
            "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
            (doc_id, session["user_id"])
        ).fetchone()
        if not doc:
            abort(404)
        path = UPLOAD_DIR / doc["stored_name"]
        if path.exists():
            path.unlink()
        db.execute("DELETE FROM documents WHERE id = ? AND owner_id = ?", (doc_id, session["user_id"]))
    flash("Документ удалён.", "success")
    return redirect(url_for("documents"))

@app.errorhandler(413)
def too_large(_error):
    return "Файл слишком большой. Максимальный размер — 50 МБ.", 413

init_db()

if __name__ == "__main__":
    # Для тестирования. Для публикации используйте production-сервер.
    app.run(host="127.0.0.1", port=5000, debug=True)
