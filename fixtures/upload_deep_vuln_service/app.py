from __future__ import annotations

import os
import pickle
import sqlite3
import subprocess
from pathlib import Path

import requests
from flask import Flask, request

app = Flask(__name__)
DB_PATH = Path(__file__).with_name("demo.db")
DATA_DIR = Path(__file__).with_name("data")


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/search")
def search_user():
    user = request.args.get("user", "")
    query = "SELECT id, name FROM users WHERE name = '" + user + "'"
    db = get_db()
    rows = db.execute(query).fetchall()
    return {"rows": rows}


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    cmd = "ping -n 1 " + host
    output = subprocess.check_output(cmd, shell=True, text=True)
    return {"output": output[:200]}


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    response = requests.get(url, timeout=2)
    return {"status": response.status_code, "sample": response.text[:120]}


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return "<h1>Hello " + name + "</h1>"


@app.route("/download")
def download_file():
    filename = request.args.get("file", "public.txt")
    path = DATA_DIR / filename
    return open(path, encoding="utf-8").read()


@app.route("/load-session", methods=["POST"])
def load_session():
    payload = request.get_data()
    session_obj = pickle.loads(payload)
    return {"loaded": bool(session_obj)}


@app.route("/safe-search")
def safe_search():
    user = request.args.get("user", "")
    db = get_db()
    rows = db.execute("SELECT id, name FROM users WHERE name = ?", (user,)).fetchall()
    return {"rows": rows}


@app.route("/profile")
def profile():
    account_id = request.args.get("accountId", "")
    current_user = request.headers.get("X-User", "anonymous")
    if account_id == current_user:
        return {"profile": account_id}
    return {"error": "not found"}, 404


if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / "public.txt").write_text("public data\n", encoding="utf-8")
    if not DB_PATH.exists():
        db = sqlite3.connect(DB_PATH)
        db.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT)")
        db.execute("INSERT INTO users(name) VALUES ('alice')")
        db.commit()
    app.run("127.0.0.1", 5005)

