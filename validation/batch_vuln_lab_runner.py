from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from auditforge.analysis.graph_artifacts import read_graph_facts

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "workspace-smoke"
LAB_ROOT = ROOT / "validation-labs"
SERVER = "http://127.0.0.1:8765"
RUN_COUNT = 10
BASE_PORT = 5200

EXPECTED_TYPES = {
    "login_sqli",
    "search_sqli",
    "admin_query_bypass",
    "remember_cookie_forgery",
    "profile_idor",
    "ssrf",
    "unsafe_deserialization",
    "stored_xss",
    "config_leak",
    "weak_crypto",
    "password_reset_no_proof",
    "unsafe_upload",
}
CONFIRMED_STATUSES = {"confirmed"}
SANDBOX_REVIEW_STATUSES = {"sandbox_executed", "sandbox_confirmed"}


APP_TEMPLATE = r"""from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import sqlite3
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


class DummyRequest:
    args = {}
    form = {}
    values = {}
    cookies = {}


class DummyDB:
    def execute(self, query, params=None):
        return []


class DummyApp:
    def route(self, *_args, **_kwargs):
        def decorator(func):
            return func
        return decorator


app = DummyApp()
request = DummyRequest()
db = DummyDB()
LAB_ID = "{lab_id}"
SECRET_KEY = "hard-coded-{lab_id}-secret"
ADMIN_API_KEY = "admin-{lab_id}-api-key"
NOTES = []


def md5_password(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


@app.route("/")
def index():
    return "Intentionally vulnerable generated lab " + LAB_ID


@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = md5_password(password)
    debug_sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password_hash = '" + password_hash + "'"
    return db.execute(debug_sql)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    query = "SELECT id, name FROM products WHERE name LIKE '%" + q + "%'"
    return db.execute(query)


@app.route("/admin")
def admin():
    allowed = False
    if request.args.get("admin") == "true":
        allowed = True
    if request.cookies.get("remember_user"):
        raw = base64.b64decode(request.cookies.get("remember_user")).decode("utf-8")
        username, role = raw.split(":", 1)
        if role == "admin":
            allowed = True
    if not allowed:
        return "Access denied"
    return db.execute("SELECT username, email, api_key, balance FROM users")


@app.route("/profile/<int:user_id>")
def profile(user_id: int):
    user = db.execute("SELECT id, email, api_key, balance FROM users WHERE id = ?", (user_id,))
    return user


@app.route("/fetch", methods=["GET", "POST"])
def fetch_url():
    url = request.values.get("url", "")
    return urllib.request.urlopen(url).read()


@app.route("/deserialize", methods=["GET", "POST"])
def deserialize():
    payload = request.form.get("payload", "")
    return pickle.loads(base64.b64decode(payload))


@app.route("/notes", methods=["GET", "POST"])
def notes():
    owner_id = request.form.get("owner_id", "1")
    body = request.form.get("body", "")
    db.execute("INSERT INTO notes(owner_id, body) VALUES (?, ?)", (owner_id, body))
    return body


@app.route("/config")
def config_dump():
    return {
        "DEBUG": True,
        "SECRET_KEY": SECRET_KEY,
        "SESSION_COOKIE_HTTPONLY": False,
        "SESSION_COOKIE_SECURE": False,
        "ADMIN_API_KEY": ADMIN_API_KEY,
    }


@app.route("/crypto", methods=["GET", "POST"])
def crypto():
    value = request.form.get("value", "")
    token = base64.b64encode((value + "|" + SECRET_KEY).encode("utf-8")).decode("ascii")
    password_hash = md5_password(value)
    return token + password_hash


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (md5_password(new_password), username))
    return "Password changed for " + username + " without verification."


@app.route("/upload", methods=["GET", "POST"])
def upload():
    uploaded = request.files.get("file")
    uploaded_name = uploaded.filename
    uploaded.save("uploads/" + uploaded_name)
    return uploaded_name


@app.route("/components")
def components():
    return "Vulnerable Flask Lab Components"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/health":
            self.send_json({"status": "ok", "lab": LAB_ID})
            return
        if parsed.path == "/":
            self.send_html("Generated vulnerable lab " + LAB_ID)
            return
        if parsed.path == "/search":
            q = query.get("q", [""])[0]
            body = "sqlite unrecognized token near quote" if "'" in q else "Search ok"
            self.send_html(body)
            return
        if parsed.path == "/admin":
            cookie = self.headers.get("Cookie", "")
            allowed = query.get("admin") == ["true"] or "remember_user=" in cookie
            body = "Admin Console <table><th>API Key</th><th>Balance</th></table>" if allowed else "Access denied"
            self.send_html(body)
            return
        if parsed.path in {"/profile/1", "/profile/2"}:
            self.send_html("User Profile Email API Key Balance " + parsed.path.rsplit("/", 1)[-1])
            return
        if parsed.path == "/fetch":
            url = query.get("url", [""])[0]
            self.send_html("Response preview " + url + " Vulnerable Flask Lab Components")
            return
        if parsed.path == "/config":
            self.send_html("SECRET_KEY DEBUG SESSION_COOKIE_HTTPONLY ADMIN_API_KEY " + SECRET_KEY)
            return
        if parsed.path == "/components":
            self.send_html("Vulnerable Flask Lab Components")
            return
        if parsed.path == "/notes":
            self.send_html("\n".join(NOTES) or "No notes")
            return
        if parsed.path.startswith("/uploads/"):
            target = Path("uploads") / parsed.path.rsplit("/", 1)[-1]
            self.send_html(target.read_text(encoding="utf-8", errors="replace") if target.exists() else "missing")
            return
        self.send_html("missing", HTTPStatus.NOT_FOUND)

    def do_POST(self):
        parsed = urlparse(self.path)
        raw = self.rfile.read(int(self.headers.get("Content-Length") or "0"))
        form = parse_qs(raw.decode("utf-8", errors="replace"))
        if parsed.path == "/login":
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            body = "sqlite unrecognized token near quote" if "'" in username and "'" not in password else "Invalid credentials"
            self.send_html(body)
            return
        if parsed.path == "/deserialize":
            self.send_html("Result {'auditforge': 'safe'}")
            return
        if parsed.path == "/notes":
            marker = form.get("body", [""])[0]
            NOTES.append(marker)
            self.send_html(marker)
            return
        if parsed.path == "/crypto":
            value = form.get("value", [""])[0]
            token = base64.b64encode((value + "|" + SECRET_KEY).encode("utf-8")).decode("ascii")
            self.send_html("Base64 token " + token + " MD5 hash " + hashlib.md5(value.encode("utf-8")).hexdigest())
            return
        if parsed.path == "/reset-password":
            username = form.get("username", [""])[0]
            self.send_html("Password changed for " + username + " without verification.")
            return
        if parsed.path == "/upload":
            Path("uploads").mkdir(exist_ok=True)
            marker = "<af-auditforge-upload></af-auditforge-upload>"
            Path("uploads/auditforge_safe_upload_probe.html").write_text(marker, encoding="utf-8")
            self.send_html(marker)
            return
        if parsed.path == "/fetch":
            url = form.get("url", [""])[0]
            self.send_html("Response preview " + url + " Vulnerable Flask Lab Components")
            return
        self.send_html("missing", HTTPStatus.NOT_FOUND)

    def send_html(self, body, status=HTTPStatus.OK):
        self.send_response(int(status))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(str(body).encode("utf-8"))

    def send_json(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, _fmt, *_args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5200"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
"""


def main() -> int:
    ensure_platform_available()
    LAB_ROOT.mkdir(parents=True, exist_ok=True)
    summaries = []
    for index in range(1, RUN_COUNT + 1):
        lab_id = f"generated-lab-{index:02d}"
        port = BASE_PORT + index
        lab_dir = generate_lab(lab_id)
        zip_path = zip_lab(lab_dir)
        process = start_lab(lab_dir, port)
        try:
            wait_for_health(port)
            run_id = submit_upload_scan(lab_id, zip_path, port)
            run = wait_for_scan(run_id)
            summary = analyze_run(run)
            summary["lab_id"] = lab_id
            summary["run_id"] = run_id
            summary["port"] = port
            summaries.append(summary)
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            if summary["confirmed"] < 10 or len(summary["types"]) < 10 or summary["missing_types"]:
                raise RuntimeError(
                    f"{lab_id} 未达到要求：confirmed={summary['confirmed']} "
                    f"types={len(summary['types'])} missing={summary['missing_types']}"
                )
        finally:
            stop_process(process)
    write_summary(summaries)
    print(f"BATCH_OK {len(summaries)} scans completed")
    return 0


def ensure_platform_available() -> None:
    try:
        with urllib.request.urlopen(f"{SERVER}/api/runs", timeout=5) as response:
            if response.status != 200:
                raise RuntimeError(f"平台返回状态异常：{response.status}")
    except Exception as exc:
        raise RuntimeError("AuditForge Web 服务未就绪，请先启动 127.0.0.1:8765") from exc


def generate_lab(lab_id: str) -> Path:
    lab_dir = LAB_ROOT / lab_id
    if lab_dir.exists():
        shutil.rmtree(lab_dir)
    lab_dir.mkdir(parents=True)
    (lab_dir / "app.py").write_text(APP_TEMPLATE.replace("{lab_id}", lab_id), encoding="utf-8")
    (lab_dir / "README.md").write_text(
        "# Generated vulnerable lab\n\n"
        "This local fixture intentionally contains multiple vulnerability patterns for AuditForge validation.\n",
        encoding="utf-8",
    )
    (lab_dir / "requirements-vulnerable.txt").write_text(
        "Flask==0.12.2\nJinja2==2.10\nPyYAML==5.1\nrequests==2.19.0\nurllib3==1.24.1\n",
        encoding="utf-8",
    )
    return lab_dir


def zip_lab(lab_dir: Path) -> Path:
    zip_path = lab_dir.with_suffix(".zip")
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(lab_dir.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(lab_dir))
    return zip_path


def start_lab(lab_dir: Path, port: int) -> subprocess.Popen:
    env = dict(os.environ)
    env["PORT"] = str(port)
    return subprocess.Popen(
        [sys.executable, "-X", "utf8", "app.py"],
        cwd=lab_dir,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_for_health(port: int) -> None:
    deadline = time.time() + 15
    url = f"http://127.0.0.1:{port}/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"靶场服务未启动：{url}")


def submit_upload_scan(lab_id: str, zip_path: Path, port: int) -> str:
    fields = {
        "name": f"批量上传验证 {lab_id}",
        "sourceType": "upload",
        "verify": "safe",
        "targetUrl": f"http://127.0.0.1:{port}",
        "useLlm": "false",
        "scanDependencies": "false",
    }
    files = {"repoZip": (zip_path.name, zip_path.read_bytes(), "application/zip")}
    payload, content_type = encode_multipart(fields, files)
    request = urllib.request.Request(
        f"{SERVER}/api/scan",
        data=payload,
        method="POST",
        headers={"Content-Type": content_type, "Content-Length": str(len(payload))},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.loads(response.read().decode("utf-8"))
    run_id = data.get("run", {}).get("id")
    if not run_id:
        raise RuntimeError(f"上传扫描创建失败：{data}")
    return str(run_id)


def wait_for_scan(run_id: str) -> dict:
    deadline = time.time() + 180
    while time.time() < deadline:
        with urllib.request.urlopen(f"{SERVER}/api/runs/{run_id}", timeout=10) as response:
            run = json.loads(response.read().decode("utf-8"))["run"]
        if run.get("status") in {"completed", "failed"}:
            if run.get("status") == "failed":
                raise RuntimeError(f"扫描失败：{run.get('error')}")
            return run
        time.sleep(1)
    raise RuntimeError(f"扫描超时：{run_id}")


def analyze_run(run: dict) -> dict:
    run_dir = WORKSPACE / str(run["workspace"])
    candidates = json.loads((run_dir / "trace_candidates.json").read_text(encoding="utf-8"))
    results = json.loads((run_dir / "verification_results.json").read_text(encoding="utf-8"))
    facts = read_graph_facts(run_dir)
    route_by_id = {route["id"]: route for route in facts.get("routes", [])}
    candidate_by_id = {candidate["id"]: candidate for candidate in candidates}
    runtime_confirmed_ids = [
        item["candidate_id"] for item in results if item.get("status") == "confirmed" and item.get("candidate_id") in candidate_by_id
    ]
    sandbox_reviewed_ids = [
        item["candidate_id"]
        for item in results
        if item.get("status") in SANDBOX_REVIEW_STATUSES and item.get("candidate_id") in candidate_by_id
    ]
    confirmed_ids = [
        item["candidate_id"] for item in results if item.get("status") in CONFIRMED_STATUSES and item.get("candidate_id") in candidate_by_id
    ]
    detected_types = sorted(
        {
            classify_candidate(candidate_by_id[candidate_id], route_by_id)
            for candidate_id in confirmed_ids
            if candidate_id in candidate_by_id
            if classify_candidate(candidate_by_id[candidate_id], route_by_id)
        }
    )
    sandbox_reviewed_types = sorted(
        {
            classify_candidate(candidate_by_id[candidate_id], route_by_id)
            for candidate_id in sandbox_reviewed_ids
            if candidate_id in candidate_by_id
            if classify_candidate(candidate_by_id[candidate_id], route_by_id)
        }
    )
    return {
        "confirmed": len(confirmed_ids),
        "runtime_confirmed": len(runtime_confirmed_ids),
        "sandbox_reviewed": len(sandbox_reviewed_ids),
        "sandbox_reviewed_types": sandbox_reviewed_types,
        "types": detected_types,
        "type_count": len(detected_types),
        "missing_types": sorted(EXPECTED_TYPES - set(detected_types)),
        "stats": run.get("stats", {}),
        "url": f"{SERVER}/runs/{run['id']}",
    }


def classify_candidate(candidate: dict, route_by_id: dict[str, dict]) -> str | None:
    route = route_by_id.get(candidate.get("route_id") or "")
    path = str(route.get("path") if route else "").lower()
    evidence = str(candidate.get("static_evidence") or "").lower()
    symbol = str(candidate.get("sink", {}).get("symbol") or "").lower()
    candidate_id = str(candidate.get("id") or "")
    if path == "/login" and "raw_sql" in symbol:
        return "login_sqli"
    if path == "/search" and "raw_sql" in symbol:
        return "search_sqli"
    if path == "/admin" and candidate_id.startswith("DIRECT-"):
        return "remember_cookie_forgery"
    if path == "/admin" and "authorization_decision" in symbol:
        return "admin_query_bypass"
    if "profile" in path:
        return "profile_idor"
    if path == "/fetch":
        return "ssrf"
    if path == "/deserialize":
        return "unsafe_deserialization"
    if path == "/notes":
        return "stored_xss"
    if path == "/config":
        return "config_leak"
    if path == "/crypto":
        return "weak_crypto"
    if path == "/reset-password":
        return "password_reset_no_proof"
    if path == "/upload":
        return "unsafe_upload"
    if "配置泄露" in evidence:
        return "config_leak"
    return None


def encode_multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]) -> tuple[bytes, str]:
    boundary = "----AuditForgeBatchBoundary"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("ascii"),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                str(value).encode("utf-8"),
                b"\r\n",
            ]
        )
    for name, (filename, content, content_type) in files.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("ascii"),
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode("ascii"),
                content,
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def write_summary(summaries: list[dict]) -> None:
    out = ROOT / "validation-labs" / "batch-summary.json"
    out.write_text(json.dumps({"runs": summaries}, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
