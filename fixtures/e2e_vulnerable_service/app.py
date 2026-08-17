"""Deliberately vulnerable local fixture for AuditForge regression tests.

Do not deploy this application or expose it to a network.  It exists only as
source input for the scanner's end-to-end security regression suite.
"""

from pathlib import Path
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)


class DemoDatabase:
    def execute(self, statement: str) -> str:
        return statement


class AccountManager:
    def get(self, *, pk: str, **scope: object) -> dict[str, str]:
        del scope
        return {"id": pk, "owner": "another-user"}


class Account:
    objects = AccountManager()


db = DemoDatabase()
DATA_ROOT = Path("/srv/auditforge-demo-data")


@app.get("/search")
def search() -> str:
    term = request.args.get("term", "")
    statement = "SELECT * FROM products WHERE name = '" + term + "'"
    return db.execute(statement)


@app.get("/preview")
def preview() -> str:
    title = request.args.get("title", "")
    return f"<h1>{title}</h1>"


@app.get("/fetch")
def fetch() -> str:
    target_url = request.args.get("url", "")
    return requests.get(target_url, timeout=2).text


@app.get("/export")
def export() -> str:
    filename = request.args.get("filename", "")
    with open(DATA_ROOT / filename, encoding="utf-8") as exported_file:
        return exported_file.read()


@app.get("/diagnostics")
def diagnostics() -> str:
    host = request.args.get("host", "")
    return subprocess.check_output(f"ping -n 1 {host}", shell=True, text=True)


@app.get("/accounts")
def account() -> dict[str, str]:
    account_id = request.args.get("account_id", "")
    return Account.objects.get(pk=account_id)
