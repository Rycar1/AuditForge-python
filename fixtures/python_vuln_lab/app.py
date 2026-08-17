from __future__ import annotations

import base64
import os
import pickle
import sqlite3
import subprocess
from pathlib import Path

import requests
from flask import Flask, jsonify, redirect, render_template_string, request, send_file, session
from markupsafe import escape

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
UPLOAD_DIR = ROOT / "uploads"
DB_PATH = DATA_DIR / "lab.db"

app = Flask(__name__)
app.secret_key = "dev-secret-key"


def connect_db() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    (UPLOAD_DIR / "public.txt").write_text("public download\n", encoding="utf-8")
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            DELETE FROM users;
            DELETE FROM notes;
            INSERT INTO users(id, username, password, role) VALUES
                (1, 'alice', 'alice123', 'user'),
                (2, 'admin', 'admin123', 'admin');
            INSERT INTO notes(id, owner_id, title, body) VALUES
                (1, 1, 'welcome', 'hello alice'),
                (2, 2, 'ops', 'admin only note');
            """
        )


@app.get("/")
def index():
    return jsonify(
        {
            "app": "python-vuln-lab",
            "routes": [
                "/search?q=alice",
                "/hello?name=alice",
                "/fetch?url=http://127.0.0.1:5005/",
                "/ping?host=127.0.0.1",
                "/download?file=public.txt",
                "/render?template={{7*7}}",
                "/admin/report?role=admin",
            ],
        }
    )


@app.get("/search")
def vulnerable_search():
    q = request.args.get("q", "")
    sql = "SELECT id, username, role FROM users WHERE username LIKE '%" + q + "%'"
    with connect_db() as db:
        rows = db.execute(sql).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/safe-search")
def safe_search():
    q = request.args.get("q", "")
    with connect_db() as db:
        rows = db.execute("SELECT id, username, role FROM users WHERE username LIKE ?", (f"%{q}%",)).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <form method="post">
          <input name="username">
          <input name="password" type="password">
          <button>login</button>
        </form>
        """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    with connect_db() as db:
        user = db.execute(sql).fetchone()
    if user:
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return redirect("/profile")
    return "login failed", 401


@app.get("/profile")
def profile():
    user_id = request.args.get("user_id") or session.get("user_id", 1)
    sql = f"SELECT id, username, role FROM users WHERE id = {user_id}"
    with connect_db() as db:
        user = db.execute(sql).fetchone()
    return jsonify(dict(user) if user else {})


@app.get("/hello")
def reflected_xss():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.get("/safe-hello")
def safe_hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + escape(name) + "</h1>"


@app.get("/render")
def template_injection():
    template = request.args.get("template", "Hello {{ name }}")
    return render_template_string(template, name="guest")


@app.get("/fetch")
def ssrf():
    url = request.args.get("url", "")
    response = requests.get(url, timeout=2)
    return response.text[:500]


@app.get("/safe-fetch")
def safe_fetch():
    url = request.args.get("url", "")
    if not url.startswith("https://example.com/"):
        return "blocked by allowlist", 400
    response = requests.get(url, timeout=2)
    return response.text[:500]


@app.get("/ping")
def command_injection():
    host = request.args.get("host", "127.0.0.1")
    flag = "-n" if os.name == "nt" else "-c"
    output = subprocess.check_output(f"ping {flag} 1 " + host, shell=True, text=True, timeout=4)
    return "<pre>" + output + "</pre>"


@app.get("/download")
def path_traversal():
    filename = request.args.get("file", "public.txt")
    path = os.path.join(UPLOAD_DIR, filename)
    return send_file(path)


@app.post("/import-profile")
def insecure_deserialization():
    blob = request.form.get("data", "")
    profile = pickle.loads(base64.b64decode(blob))
    return jsonify({"loaded": str(profile)})


@app.get("/admin/report")
def authz_bypass():
    role = request.args.get("role", "user")
    if role == "admin":
        return jsonify({"revenue": 1000000, "export": "admin-report.csv"})
    return "forbidden", 403


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5005, debug=True)
