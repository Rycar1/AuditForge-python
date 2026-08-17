from flask import Flask, request
import sqlite3
import requests

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q")
    db = sqlite3.connect("app.db")
    rows = db.execute("select * from users where name = '" + q + "'").fetchall()
    return str(rows)


@app.route("/profile")
def profile():
    name = request.args.get("name")
    return "<h1>" + name + "</h1>"


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text


@app.route("/safe")
def safe():
    user_id = int(request.args.get("id", "0"))
    db = sqlite3.connect("app.db")
    rows = db.execute("select * from users where id = ?", [user_id]).fetchall()
    return str(rows)
