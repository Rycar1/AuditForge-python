from __future__ import annotations

from pathlib import Path

from auditforge.candidates import build_trace_candidates
from auditforge.graph import build_graph
from auditforge.llm_candidates import (
    LLMConfig,
    generate_llm_candidates,
    normalize_one_candidate,
    plan_llm_audit_tasks,
)
from auditforge.scanner import scan_repo
from auditforge.semantic_findings import generate_semantic_candidates


def _scan_all(repo: Path) -> list:
    facts = scan_repo(repo)
    candidates = build_trace_candidates(facts, build_graph(facts))
    candidates.extend(generate_semantic_candidates(repo, facts, candidates))
    return candidates


def test_python_constant_folding_and_dead_branch_pruning(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\n"
        "from flask import request\n"
        "def safe_dead_branch():\n"
        "    user_input = request.args.get('p', '')\n"
        "    threshold = 120\n"
        "    if 2 * 50 + threshold > 200:\n"
        "        cmd = 'safe'\n"
        "    else:\n"
        "        cmd = user_input\n"
        "    os.system(cmd)\n"
        "def vulnerable_live_branch():\n"
        "    user_input = request.args.get('p', '')\n"
        "    threshold = 120\n"
        "    if 2 * 50 + threshold > 200:\n"
        "        cmd = user_input\n"
        "    else:\n"
        "        cmd = 'safe'\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    sink_lines = {c.sink.start_line for c in candidates if c.vuln_class == "injection"}
    assert 10 not in sink_lines
    assert 18 in sink_lines


def test_python_containers_loops_wrapper_class_and_response_xss(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import make_response, request\n"
        "class RequestWrapper:\n"
        "    def __init__(self, req):\n"
        "        self.req = req\n"
        "    def get_param(self, key):\n"
        "        return self.req.args.get(key, '')\n"
        "def wrapped_and_xss():\n"
        "    scr = RequestWrapper(request)\n"
        "    raw = scr.get_param('name').strip()\n"
        "    items = ['safe', raw, 'tail']\n"
        "    picked = items[1]\n"
        "    mapping = {'a': 'ok', 'b': picked}\n"
        "    val = ''\n"
        "    for item in [mapping.get('b')]:\n"
        "        val = item\n"
        "    html = '<div>' + val + '</div>'\n"
        "    return make_response(html)\n",
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    xss = [c for c in candidates if c.vuln_class == "xss"]
    assert len(xss) >= 1
    assert any(c.sink.start_line == 17 for c in xss)


def test_python_crypto_weak_random_cookie_and_injection_categories(tmp_path: Path) -> None:
    (tmp_path / "crypto_and_sinks.py").write_text(
        "import hashlib\n"
        "import random\n"
        "import secrets\n"
        "import ldap3\n"
        "from Crypto.Cipher import AES, DES\n"
        "from flask import Flask, make_response, redirect, request, session\n"
        "from lxml import etree\n"
        "app = Flask(__name__)\n"
        "@app.get('/weak')\n"
        "def weak_cases():\n"
        "    user_in = request.args.get('q', '')\n"
        "    d1 = hashlib.md5(user_in.encode()).hexdigest()\n"
        "    c1 = DES.new(b'12345678', DES.MODE_ECB)\n"
        "    rand_val = str(random.randint(1000, 9999))\n"
        "    resp = make_response(d1 + str(c1))\n"
        "    resp.set_cookie('sid', rand_val)\n"
        "    session['item'] = user_in\n"
        "    return redirect(user_in)\n"
        "@app.get('/injections')\n"
        "def injection_cases(conn, tree):\n"
        "    x = request.args.get('x', '')\n"
        "    eval(x)\n"
        "    conn.search('dc=example', f'(uid={x})')\n"
        "    tree.xpath(f'//user[name={x}]')\n"
        "    etree.fromstring(x.encode())\n"
        "@app.get('/safe')\n"
        "def safe_cases():\n"
        "    data = b'abc'\n"
        "    ok_hash = hashlib.md5(data, usedforsecurity=False).hexdigest()\n"
        "    ok_cipher = AES.new(b'0' * 16, AES.MODE_GCM)\n"
        "    ok_tok = secrets.token_hex(16)\n"
        "    resp = make_response(ok_hash + str(ok_cipher))\n"
        "    resp.set_cookie('sid', ok_tok, secure=True)\n"
        "    return resp\n",
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    cwes = {cwe for c in candidates for cwe in (c.cwe_ids or [])}
    assert "CWE-328" in cwes or "CWE-327" in cwes
    assert "CWE-330" in cwes or "CWE-338" in cwes
    assert "CWE-614" in cwes
    assert "CWE-501" in cwes
    assert "CWE-601" in cwes
    assert "CWE-94" in cwes or "CWE-95" in cwes
    assert "CWE-90" in cwes
    assert "CWE-643" in cwes
    assert "CWE-611" in cwes
    # Safe route lines 29..34 should not trigger weak_hash / weak_cipher / weak_random / insecure_cookie
    safe_hits = [c for c in candidates if 27 <= c.sink.start_line <= 35]
    assert safe_hits == []


def test_java_servlet_constant_folding_crypto_sanitizers_and_system_out_exclusion(tmp_path: Path) -> None:
    (tmp_path / "RequestAdapter.java").write_text(
        "import javax.servlet.http.HttpServletRequest;\n"
        "public class RequestAdapter {\n"
        "    private HttpServletRequest request;\n"
        "    public RequestAdapter(HttpServletRequest req) { this.request = req; }\n"
        "    public String getTheParameter(String name) {\n"
        "        return request.getParameter(name);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "TestServlet.java").write_text(
        "import java.io.*;\n"
        "import java.security.*;\n"
        "import java.util.*;\n"
        "import javax.crypto.Cipher;\n"
        "import javax.servlet.annotation.WebServlet;\n"
        "import javax.servlet.http.*;\n"
        "import org.owasp.esapi.ESAPI;\n"
        '@WebServlet("/vuln/test")\n'
        "public class TestServlet extends HttpServlet {\n"
        "    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        "        RequestAdapter adapter = new RequestAdapter(request);\n"
        '        String rawId = adapter.getTheParameter("id");\n'
        "        String tainted = new InnerHelper().doSomething(rawId);\n"
        "        int threshold = 90;\n"
        '        String cmdTarget = (3 * 50 - threshold > 40) ? "safe" : tainted;\n'
        '        if ("safe".equals(cmdTarget)) {\n'
        "            System.out.println(tainted);\n"
        "        }\n"
        "        List<String> list = new ArrayList<>();\n"
        '        list.add("safe");\n'
        "        list.add(tainted);\n"
        "        list.remove(0);\n"
        "        String fromList = list.get(0);\n"
        "        new FileInputStream(fromList);\n"
        "        String safeHtml = ESAPI.encoder().encodeForHTML(tainted);\n"
        "        response.getWriter().println(safeHtml);\n"
        '        MessageDigest mdWeak = MessageDigest.getInstance("MD5");\n'
        '        MessageDigest mdSafe = MessageDigest.getInstance("SHA-256");\n'
        '        Cipher cWeak = Cipher.getInstance("DES/CBC/PKCS5Padding");\n'
        '        Cipher cSafeRsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");\n'
        "        Random r = new Random();\n"
        "        String tok = String.valueOf(r.nextInt());\n"
        '        Cookie ck = new Cookie("sid", tok);\n'
        "        response.addCookie(ck);\n"
        '        Cookie okCk = new Cookie("ok", "1");\n'
        "        okCk.setSecure(true);\n"
        "        response.addCookie(okCk);\n"
        '        request.getSession().setAttribute("k", tainted);\n'
        "        response.sendRedirect(tainted);\n"
        "        Runtime.getRuntime().exec(cmdTarget);\n"
        "    }\n"
        "    public class InnerHelper {\n"
        "        public String doSomething(String arg) { return arg; }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    assert any(r.path == "/vuln/test" and r.method == "POST" for r in facts.routes)
    candidates = build_trace_candidates(facts, build_graph(facts))
    candidates.extend(generate_semantic_candidates(tmp_path, facts, candidates))

    # Path traversal from RequestAdapter -> InnerHelper -> ArrayList add/remove/get -> FileInputStream
    assert any(c.taxonomy_id == "path_traversal" and c.sink.start_line == 24 for c in candidates)
    # Trust boundary & open redirect
    assert any(c.taxonomy_id == "trust_boundary_violation" for c in candidates)
    assert any(c.taxonomy_id == "open_redirect" for c in candidates)
    # Weak hash only on MD5 (line 27), not SHA-256 (line 28)
    weak_hashes = [c for c in candidates if c.taxonomy_id == "weak_cryptography" and c.sink.start_line in {27, 28}]
    assert [c.sink.start_line for c in weak_hashes] == [27]
    # Weak cipher only on DES (line 29), not RSA/ECB/OAEP (line 30)
    weak_ciphers = [c for c in candidates if c.taxonomy_id == "weak_cryptography" and c.sink.start_line in {29, 30}]
    assert [c.sink.start_line for c in weak_ciphers] == [29]
    # Weak random & insecure cookie only on ck without setSecure(true) (line 34), not okCk (line 37)
    assert any(c.taxonomy_id == "insecure_randomness" for c in candidates)
    insecure_cookies = [c for c in candidates if c.taxonomy_id == "insecure_cookie"]
    assert [c.sink.start_line for c in insecure_cookies] == [34]
    # System.out.println and ESAPI-encoded output must not emit XSS
    assert [c for c in candidates if c.vuln_class == "xss"] == []
    # Constant-folded ternary ("safe") must not emit command_injection at Runtime.getRuntime().exec(cmdTarget)
    assert [c for c in candidates if c.taxonomy_id == "command_injection"] == []


def test_llm_budget_sharding_and_native_cwe_inheritance(tmp_path: Path, monkeypatch) -> None:
    for idx in range(12):
        (tmp_path / f"mod_{idx:02d}.py").write_text(
            "from flask import Flask, request\n"
            "import subprocess\n"
            f"def handler_{idx}():\n"
            f"    val = request.args.get('v{idx}', '')\n"
            "    return val\n",
            encoding="utf-8",
        )
    facts = scan_repo(tmp_path)
    tasks = plan_llm_audit_tasks(facts)
    # Multiple files > 8 should not be compressed back down to tiny truncated bins if packed scopes differ,
    # and all 12 files must remain represented across planned scopes.
    covered_files = {f for task in tasks for f in task.files}
    assert {f"mod_{idx:02d}.py" for idx in range(12)} <= covered_files

    raw_with_cwes = {
        "vulnClass": "injection",
        "taxonomyId": "command_injection",
        "cweIds": ["cwe-78"],
        "source": {"file": "mod_00.py", "startLine": 4},
        "sink": {"file": "mod_00.py", "startLine": 5},
        "steps": [
            {
                "kind": "assignment",
                "from": {"file": "mod_00.py", "startLine": 4},
                "to": {"file": "mod_00.py", "startLine": 5},
                "explanation": "从请求参数流向执行点。",
                "confidence": "high",
            }
        ],
        "sanitizers": [],
        "blockers": [],
        "confidence": "medium",
        "staticEvidence": "mod_00.py:4 参数流入 mod_00.py:5。",
        "verificationHint": "使用无害测试输入验证边界。",
        "notes": [],
    }
    cand = normalize_one_candidate(tmp_path, raw_with_cwes, 1, {("mod_00.py", 4), ("mod_00.py", 5)})
    assert cand.cwe_ids == ["CWE-78"]
    assert cand.taxonomy_id == "command_injection"

    # Also test generate_llm_candidates CWE inheritance when SinkFact overlaps and LLM omits cweIds
    (tmp_path / "app_llm.py").write_text(
        "from flask import request\n"
        "import sqlite3\n"
        "def run_q():\n"
        "    user = request.args.get('u', '')\n"
        "    sqlite3.connect(':memory:').execute(user)\n",
        encoding="utf-8",
    )
    facts2 = scan_repo(tmp_path)
    monkeypatch.setattr(
        "auditforge.llm_candidates.run_llm_audit_task",
        lambda prompt, config: {
            "candidates": [
                {
                    "vulnClass": "injection",
                    "source": {"file": "app_llm.py", "startLine": 4},
                    "sink": {"file": "app_llm.py", "startLine": 5},
                    "steps": [
                        {
                            "kind": "assignment",
                            "from": {"file": "app_llm.py", "startLine": 4},
                            "to": {"file": "app_llm.py", "startLine": 5},
                            "explanation": "请求参数直接进入 SQL execute。",
                            "confidence": "high",
                        }
                    ],
                    "sanitizers": [],
                    "blockers": [],
                    "confidence": "high",
                    "staticEvidence": "app_llm.py:4 输入直接进入 app_llm.py:5 SQL 执行。",
                    "verificationHint": "使用单引号边界输入测试。",
                    "notes": [],
                }
            ]
        },
    )
    accepted, _diag = generate_llm_candidates(
        tmp_path,
        facts2,
        [],
        config=LLMConfig(enabled=True, concurrency=2, max_candidates=10),
    )
    assert len(accepted) >= 1
    assert accepted[0].taxonomy_id == "sql_injection"
    assert accepted[0].cwe_ids == ["CWE-89"]


def test_java_literal_leak_comments_prepared_stmt_guards_and_list_cmdi(tmp_path: Path) -> None:
    (tmp_path / "GuardAndCmdiServlet.java").write_text(
        "import java.io.*;\n"
        "import java.sql.*;\n"
        "import java.util.*;\n"
        "import javax.servlet.annotation.WebServlet;\n"
        "import javax.servlet.http.*;\n"
        "import org.owasp.esapi.ESAPI;\n"
        '@WebServlet("/vuln/batch1")\n'
        "public class GuardAndCmdiServlet extends HttpServlet {\n"
        "    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        '        String p = request.getParameter("id");\n'
        '        String results = request.getHeader("x-ldap");\n'
        "        Cookie[] cookies = request.getCookies();\n"
        "        if (cookies != null) {\n"
        "            for (Cookie cookie : cookies) {\n"
        '                if ("remember".equals(cookie.getName())) {\n'
        '                    String user = "Alice";\n'
        "                    response.getWriter().println(\n"
        '                        user + " has been remembered with cookie: " + "ok");\n'
        "                }\n"
        "            }\n"
        "        }\n"
        "        response.getWriter().println(\n"
        '            "LDAP query results: "\n'
        "                + ESAPI.encoder().encodeForHTML(results));\n"
        "        // new java.io.File(p).createNewFile();\n"
        "        Connection conn = null;\n"
        '        String safeSql = "SELECT * FROM users WHERE id = ?";\n'
        "        PreparedStatement ps = conn.prepareStatement(safeSql);\n"
        "        ps.setString(1, p);\n"
        "        ps.executeQuery();\n"
        "        Statement st = conn.createStatement();\n"
        '        if (Arrays.asList("one", "two").contains(p)) {\n'
        '            st.executeQuery("SELECT * FROM items WHERE k=" + p);\n'
        "        }\n"
        '        if (!p.startsWith("/safe/")) {\n'
        "            return;\n"
        "        }\n"
        "        new FileInputStream(p);\n"
        "        double dice = java.lang.Math.random();\n"
        "        System.out.println(dice);\n"
        "        double rnd = java.lang.Math.random();\n"
        '        response.addCookie(new Cookie("sid", Double.toString(rnd)));\n'
        "        List<String> argList = new ArrayList<>();\n"
        '        argList.add("sh");\n'
        "        argList.add(p);\n"
        "        new ProcessBuilder(argList).start();\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    # No string-literal leak ("cookie" / "results") -> zero XSS false positives
    assert [c for c in candidates if c.vuln_class == "xss"] == []
    # Commented-out File and startsWith-guarded FileInputStream must not fire path_traversal
    assert [c for c in candidates if c.taxonomy_id == "path_traversal"] == []
    # Constant PreparedStatement + Arrays.asList.contains guard must not fire sql_injection
    assert [c for c in candidates if c.taxonomy_id == "sql_injection"] == []
    # Benign Math.random() printed to stdout is ignored; Math.random() flowing to Cookie MUST be detected
    weak_lines = {c.sink.start_line for c in candidates if c.taxonomy_id == "insecure_randomness"}
    assert weak_lines == {41}
    assert any(c.taxonomy_id == "command_injection" for c in candidates)


def test_python_route_xss_without_angle_brackets_helpers_and_path_xpath_guards(tmp_path: Path) -> None:
    (tmp_path / "xss_and_guards.py").write_text(
        "import pathlib\n"
        "from lxml import etree\n"
        "from flask import Flask, Response, jsonify, request\n"
        "app = Flask(__name__)\n"
        "def escape_for_html(s):\n"
        "    return s\n"
        "def helper_command_output(stderr_txt):\n"
        "    ret = '<html>'\n"
        "    ret += escape_for_html(stderr_txt).replace('\\n', '<br>')\n"
        "    return ret\n"
        "def init(app):\n"
        "    @app.route('/xss-vuln', methods=['POST'])\n"
        "    def xss_vuln():\n"
        "        RESPONSE = ''\n"
        "        bar = request.form.get('name', '')\n"
        "        RESPONSE += f'Parameter value: {bar}'\n"
        "        return RESPONSE\n"
        "    @app.route('/xss-safe-escaped', methods=['POST'])\n"
        "    def xss_safe_escaped():\n"
        "        RESPONSE = ''\n"
        "        bar = request.form.get('name', '')\n"
        "        fobj = open('/tmp/' + bar, 'r')\n"
        "        RESPONSE += f'Read {escape_for_html(fobj.name)} and {helper_command_output(bar)}'\n"
        "        return RESPONSE\n"
        "    @app.route('/path-vuln', methods=['POST'])\n"
        "    def path_vuln():\n"
        "        bar = request.form.get('f', '')\n"
        "        base = pathlib.Path('/srv/files')\n"
        "        p = (base / bar).resolve()\n"
        "        return jsonify({'body': p.read_text()})\n"
        "    @app.route('/path-safe', methods=['POST'])\n"
        "    def path_safe():\n"
        "        bar = request.form.get('f', '')\n"
        "        base = pathlib.Path('/srv/files')\n"
        "        p = (base / bar).resolve()\n"
        "        if not str(p).startswith(str(base)):\n"
        "            return 'Invalid'\n"
        "        return Response(p.read_text(), mimetype='text/plain')\n"
        "    @app.route('/xpath-guards', methods=['POST'])\n"
        "    def xpath_guards():\n"
        "        bar = request.form.get('id', '')\n"
        "        tree = etree.fromstring(b'<root/>')\n"
        "        if bar in ('u1', 'u2'):\n"
        "            return str(tree.xpath(f\"//user[@id='{bar}']\"))\n"
        '        if "\'" in bar:\n'
        "            return 'bad'\n"
        "        return str(tree.xpath(f\"//user[@id='{bar}']\"))\n"
        "    @app.route('/trust-and-config', methods=['POST'])\n"
        "    def trust_and_config():\n"
        "        import configparser\n"
        "        import flask\n"
        "        bar = request.form.get('k', '')\n"
        "        cfg = configparser.ConfigParser()\n"
        "        cfg.add_section('sec')\n"
        "        cfg.set('sec', 'safe', 'const_val')\n"
        "        cfg.set('sec', 'tainted', bar)\n"
        "        safe_v = cfg.get('sec', 'safe')\n"
        "        vuln_v = cfg.get('sec', 'tainted')\n"
        "        flask.session[safe_v] = 'ok'\n"
        "        flask.session[vuln_v] = '1'\n"
        "        return 'ok'\n",
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    xss_lines = {c.sink.start_line for c in candidates if c.vuln_class == "xss"}
    assert 17 in xss_lines
    assert 10 not in xss_lines
    assert 24 not in xss_lines
    assert 38 not in xss_lines

    path_lines = {c.sink.start_line for c in candidates if c.taxonomy_id == "path_traversal"}
    assert 30 in path_lines
    assert 37 not in path_lines

    xpath_lines = {c.sink.start_line for c in candidates if c.taxonomy_id == "xpath_injection"}
    assert 44 not in xpath_lines
    assert 47 in xpath_lines

    tb_lines = {c.sink.start_line for c in candidates if c.taxonomy_id == "trust_boundary_violation"}
    assert 60 in tb_lines
    assert 59 not in tb_lines


def test_java_batch3_cookie_name_guard_try_resource_securerandom_and_query_results(tmp_path: Path) -> None:
    (tmp_path / "Batch3Java.java").write_text(
        """
import javax.servlet.http.*;
import java.io.*;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import javax.xml.xpath.*;

public class Batch3Java extends HttpServlet {
    private static final org.springframework.jdbc.core.JdbcTemplate JDBCtemplate = null;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cookieVal = "default";
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("sessionCookie")) {
                    cookieVal = java.net.URLDecoder.decode(cookie.getValue(), "UTF-8");
                    break;
                }
            }
        }
        String userVal = cookieVal;
        String sql = "SELECT * FROM users WHERE name='" + userVal + "'";
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        PreparedStatement ps = conn.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
        ps.execute();

        Long dbCount = JDBCtemplate.queryForObject(sql, Long.class);
        response.getWriter().println("Count: " + String.valueOf(dbCount));

        XPath xp = XPathFactory.newInstance().newXPath();
        String expr = "/users/user[@id='" + userVal + "']";
        String xres = xp.evaluate(expr, new org.xml.sax.InputSource("employees.xml"));
        response.getWriter().println("XPath result: " + xres);

        String fileName = "/srv/data/" + userVal;
        try (
            FileOutputStream fos = new FileOutputStream(new FileInputStream(fileName).getFD()); ) {
            response.getWriter().println("Opened: " + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));
        }

        if ("safe_const".equals(userVal)) {
            Statement safeSt = conn.createStatement();
            safeSt.execute("SELECT * FROM users WHERE name='" + userVal + "'");
        }

        Random secGen = SecureRandom.getInstance("SHA1PRNG");
        byte[] secBytes = new byte[16];
        secGen.nextBytes(secBytes);

        Random weakGen = new Random();
        int weakVal = generateResetToken(weakGen);

        String value = "";
        String[] paramVals = request.getParameterValues("k");
        if (paramVals != null) {
            for (int i = 0; i < paramVals.length; i++) {
                String itemVal = paramVals[i];
                if (itemVal.equals("x")) break;
            }
        }
        double itemVal = new java.util.Random().nextDouble();
        String token = Double.toString(itemVal);
        int dice = new Random().nextInt(6);
        response.getWriter().println("Token=" + token + ", weak=" + weakVal + ", dice=" + dice);
    }

    void getNextSecure(SecureRandom generator, byte[] out) {
        generator.nextBytes(out);
    }

    int generateResetToken(Random generator) {
        return generator.nextInt(100);
    }
}
""".lstrip(),
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    by_tax = {}
    for c in candidates:
        by_tax.setdefault(c.taxonomy_id, set()).add(c.sink.start_line)

    # Cookie value flows past theCookie.getName().equals(...) to PreparedStatement & XPath
    assert 26 in by_tax.get("sql_injection", set())
    assert 29 in by_tax.get("sql_injection", set())
    assert 45 not in by_tax.get("sql_injection", set())
    assert 34 in by_tax.get("xpath_injection", set())
    # try-with-resources FileOutputStream/FileInputStream emits path_traversal despite ") {"
    assert 39 in by_tax.get("path_traversal", set())
    # Safe DB count, XPath XML result, ESAPI encodeForHTML in doPost, and redeclared double scalar must not emit XSS
    xss_lines = by_tax.get("cross_site_scripting", set())
    assert 30 not in xss_lines
    assert 35 not in xss_lines
    assert 40 not in xss_lines
    assert 66 not in xss_lines
    # SecureRandom (local & typed param) is safe; benign dice roll is safe; token/reset helpers are flagged
    weak_lines = by_tax.get("insecure_randomness", set())
    assert 50 not in weak_lines
    assert 65 not in weak_lines
    assert 70 not in weak_lines
    assert 63 in weak_lines
    assert 74 in weak_lines


def test_python_batch3_xpath_isolation_stringio_list_pop_exists_and_eval_guard(tmp_path: Path) -> None:
    (tmp_path / "batch3_app.py").write_text(
        "import io\n"
        "import os\n"
        "import pathlib\n"
        "import elementpath\n"
        "import xml.etree.ElementTree as ET\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "def escape_for_html(s):\n"
        "    return s\n"
        "@app.route('/xpath-and-xss', methods=['POST'])\n"
        "def xpath_and_xss():\n"
        "    RESPONSE = ''\n"
        "    bar = request.form.get('id', '')\n"
        "    root = ET.fromstring('<employees/>')\n"
        "    query = f\"/Employees/Employee[@emplid='{bar}']\"\n"
        "    nodes = elementpath.select(root, query)\n"
        "    node_strings = [n.text or '' for n in nodes]\n"
        "    RESPONSE += f'Results:<br>[{\", \".join(node_strings)}]'\n"
        "    return RESPONSE\n"
        "@app.route('/xpath-inline-replace', methods=['POST'])\n"
        "def xpath_inline_replace():\n"
        "    bar = request.form.get('id', '')\n"
        "    root = ET.fromstring('<employees/>')\n"
        "    nodes = elementpath.select(root, f\"/Employees/Employee[@emplid='{bar.replace(\"'\", '&apos;')}']\")\n"
        "    return str(len(nodes))\n"
        "@app.route('/xpath-stringio', methods=['POST'])\n"
        "def xpath_stringio():\n"
        "    bar = request.form.get('id', '')\n"
        "    root = ET.fromstring('<employees/>')\n"
        "    buf = io.StringIO()\n"
        "    buf.write('/Employees/Employee[@emplid=\\'')\n"
        "    buf.write(bar)\n"
        "    buf.write('\\']')\n"
        "    q = buf.getvalue()\n"
        "    return str(len(elementpath.select(root, q)))\n"
        "@app.route('/path-pop-exists', methods=['POST'])\n"
        "def path_pop_exists():\n"
        "    param = request.form.get('f', '')\n"
        "    vuln_name = 'safe'\n"
        "    safe_name = 'safe'\n"
        "    if param:\n"
        "        lst = []\n"
        "        lst.append('safe')\n"
        "        lst.append(param)\n"
        "        lst.append('moresafe')\n"
        "        lst.pop(0)\n"
        "        vuln_name = lst[0]\n"
        "        safe_name = lst[1]\n"
        "    base = pathlib.Path('/srv/files')\n"
        "    p_vuln = base / vuln_name\n"
        "    p_safe = base / safe_name\n"
        "    a = 'hit' if p_vuln.exists() else 'miss'\n"
        "    b = 'hit' if os.path.exists(f'/srv/files/{safe_name}') else 'miss'\n"
        "    if '../' in vuln_name:\n"
        "        return 'bad'\n"
        "    guarded_path = f'/srv/files/{vuln_name}'\n"
        "    c_guarded = open(guarded_path).read()\n"
        "    return f'{a}-{b}-{c_guarded}'\n"
        "@app.route('/eval-guards', methods=['POST'])\n"
        "def eval_guards():\n"
        "    bar = request.form.get('code', '')\n"
        "    raw_code = request.form.get('raw_code', '')\n"
        "    r1 = eval(raw_code)\n"
        '    if not bar.startswith("\'") or not bar.endswith("\'") or "\'" in bar[1:-1]:\n'
        "        return 'invalid'\n"
        "    r2 = eval(bar)\n"
        "    return f'{r1}-{r2}'\n",
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    xpath_lines = {c.sink.start_line for c in candidates if c.taxonomy_id == "xpath_injection"}
    assert 16 in xpath_lines
    assert 24 in xpath_lines
    assert 35 in xpath_lines

    xss_lines = {c.sink.start_line for c in candidates if c.vuln_class == "xss"}
    assert 19 not in xss_lines

    path_lines = {c.sink.start_line for c in candidates if c.taxonomy_id == "path_traversal"}
    assert 52 in path_lines
    assert 53 not in path_lines
    assert 57 in path_lines

    code_lines = {c.sink.start_line for c in candidates if c.taxonomy_id == "code_injection"}
    assert 63 in code_lines
    assert 66 in code_lines


def test_general_soundness_rejects_unsound_denylists_and_benign_prng(tmp_path: Path) -> None:
    (tmp_path / "app_fastapi.py").write_text(
        "from fastapi import FastAPI, Query\n"
        "app = FastAPI()\n"
        "@app.get('/greet')\n"
        "def greet(name: str = Query('')):\n"
        "    return f'Hello {name}'\n",
        encoding="utf-8",
    )
    (tmp_path / "general_py.py").write_text(
        "import random\n"
        "from flask import Flask, make_response, request, session\n"
        "app = Flask(__name__)\n"
        "@app.route('/dice', methods=['GET'])\n"
        "def dice_and_benign():\n"
        "    spinner = random.randint(1, 6)\n"
        "    inside = random.randint(1, 6)\n"
        "    author = random.randint(1, 6)\n"
        "    valid = random.randint(1, 6)\n"
        "    if request.args.get('mode') == 'html':\n"
        "        return make_response(f'{spinner}-{inside}-{author}-{valid}')\n"
        "    return {'roll': random.randint(1, 6)}\n"
        "@app.route('/auth-rand', methods=['POST'])\n"
        "def auth_rand():\n"
        "    r = str(random.randint(1000, 9999))\n"
        "    session['csrf_nonce'] = r\n"
        "    resp = make_response('ok')\n"
        "    resp.set_cookie('sid', r)\n"
        "    return resp\n"
        "@app.route('/obj-eq', methods=['POST'])\n"
        "def obj_eq():\n"
        "    raw = request.form.get('x', '')\n"
        "    if raw.strip() == 'const':\n"
        "        eval(raw)\n",
        encoding="utf-8",
    )
    (tmp_path / "GeneralJava.java").write_text(
        """
import java.io.*;
import java.security.SecureRandom;
import java.util.Random;
import javax.servlet.http.*;
import javax.xml.xpath.*;

public class GeneralJava extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String p = req.getParameter("p");
        if (p.contains("..")) return;
        new FileInputStream("/srv/data/" + p);
        if (p.contains("'")) return;
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.evaluate("//u[@id='" + p + "']", new org.xml.sax.InputSource("x.xml"));
        int spinner = new Random().nextInt(10);
        int valid = new Random().nextInt(10);
        System.out.println(spinner + valid);
        float rk = new Random().nextFloat();
        String s = Float.toString(rk).substring(2);
        Cookie ck = new Cookie("rememberMe", s);
        resp.addCookie(ck);
        SecureRandom sr = new SecureRandom();
        generateNonce(sr, new byte[8]);
    }
    void generateNonce(Random gen, byte[] out) {
        gen.nextBytes(out);
    }
}
""".lstrip(),
        encoding="utf-8",
    )

    candidates = _scan_all(tmp_path)
    assert [c for c in candidates if c.source.file.endswith("app_fastapi.py") and c.vuln_class == "xss"] == []

    py_weak = {c.sink.start_line for c in candidates if c.source.file.endswith("general_py.py") and c.taxonomy_id == "insecure_randomness"}
    assert py_weak
    assert all(ln >= 15 for ln in py_weak)
    assert any(c.source.file.endswith("general_py.py") and c.taxonomy_id == "code_injection" for c in candidates)

    java_cands = [c for c in candidates if c.source.file.endswith("GeneralJava.java")]
    assert any(c.taxonomy_id == "path_traversal" for c in java_cands)
    assert any(c.taxonomy_id == "xpath_injection" for c in java_cands)
    java_weak = {c.sink.start_line for c in java_cands if c.taxonomy_id == "insecure_randomness"}
    assert java_weak == {18, 26}


def test_llm_evidence_review_separates_all_vs_verified_and_filters_false_positives(tmp_path: Path, monkeypatch) -> None:
    from auditforge.llm_candidates import review_candidates_with_evidence

    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import html\n"
        "import sqlite3\n"
        "def handler():\n"
        "    raw = request.args.get('q', '')\n"
        "    sqlite3.connect(':memory:').execute(raw)\n"
        "    clean = html.escape(raw)\n"
        "    return f'<p>{clean}</p>'\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)

    monkeypatch.setattr(
        "auditforge.llm_candidates.run_llm_audit_task",
        lambda prompt, config: {
            "candidates": [
                {
                    "vulnClass": "injection",
                    "taxonomyId": "sql_injection",
                    "cweIds": ["CWE-89"],
                    "source": {"file": "app.py", "startLine": 5},
                    "sink": {"file": "app.py", "startLine": 6},
                    "steps": [
                        {
                            "kind": "assignment",
                            "from": {"file": "app.py", "startLine": 5},
                            "to": {"file": "app.py", "startLine": 6},
                            "explanation": "app.py:5 请求参数进入 app.py:6 sqlite execute。",
                            "confidence": "high",
                        }
                    ],
                    "sanitizers": [],
                    "blockers": [],
                    "confidence": "high",
                    "staticEvidence": "app.py:5 用户输入直接拼接到 app.py:6 SQL 语句执行。",
                    "verificationHint": "验证引号报错。",
                    "notes": [],
                },
                {
                    "vulnClass": "xss",
                    "taxonomyId": "cross_site_scripting",
                    "cweIds": ["CWE-79"],
                    "source": {"file": "app.py", "startLine": 5},
                    "sink": {"file": "app.py", "startLine": 8},
                    "steps": [
                        {
                            "kind": "llm_inferred",
                            "from": {"file": "app.py", "startLine": 5},
                            "to": {"file": "app.py", "startLine": 8},
                            "explanation": "参数输出到响应。",
                            "confidence": "low",
                        }
                    ],
                    "sanitizers": [],
                    "blockers": [],
                    "confidence": "low",
                    "staticEvidence": "app.py:5 到 app.py:8 存在响应拼接。",
                    "verificationHint": "验证脚本标签响应。",
                    "notes": [],
                },
            ]
        },
    )

    accepted, diagnostics = generate_llm_candidates(
        tmp_path,
        facts,
        [],
        LLMConfig(enabled=True, model="mock", base_url="http://localhost:11434/v1", max_candidates=10),
    )
    assert len(accepted) == 2
    review = diagnostics["evidence_review"]
    assert review["all_count"] == 2
    assert review["verified_count"] == 1
    assert review["filtered_count"] == 1
    assert len(review["all_candidates"]) == 2
    assert len(review["verified_candidates"]) == 1
    assert review["verified_candidates"][0]["cwe_ids"] == ["CWE-89"]

    verified_direct, entries = review_candidates_with_evidence(accepted, facts)
    assert len(verified_direct) == 1
    assert any(not item["verified"] and "CWE-89" not in str(item) for item in entries)


def test_llm_triage_filters_only_grounded_high_confidence_fp_and_preserves_all(tmp_path: Path, monkeypatch) -> None:
    import json

    from auditforge.engine import run_scan
    from auditforge.llm_candidates import LLMConfig, triage_candidates_with_llm

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "secret_sqli_case.py").write_text(
        "import pathlib\n"
        "import sqlite3\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/sqli-00/secret_sqli_case', methods=['POST'])\n"
        "def f_a():\n"
        "    # expected vulnerable case\n"
        "    raw_query = request.form.get('q', '')\n"
        "    sqlite3.connect(':memory:').execute(raw_query)\n"
        "    return 'ok'\n"
        "@app.route('/pathtr-00/test_b', methods=['POST'])\n"
        "def f_b():\n"
        "    user_path = request.form.get('p', '')\n"
        "    if '../' in user_path:\n"
        "        return 'bad'\n"
        "    return open('/srv/' + user_path).read()\n"
        "@app.route('/pathtr-01/test_c', methods=['POST'])\n"
        "def f_c():\n"
        "    k_val = request.form.get('k', '')\n"
        "    if k_val == 'fixed':\n"
        "        return 'safe'\n"
        "    return open('/srv/' + k_val).read()\n"
        "@app.route('/pathtr-02/test_d', methods=['POST'])\n"
        "def f_d():\n"
        "    d_val = request.form.get('d', '')\n"
        "    return open('/srv/' + d_val).read()\n",
        encoding="utf-8",
    )
    facts = scan_repo(repo)
    cands = build_trace_candidates(facts, build_graph(facts))
    assert len(cands) >= 4
    seen_prompts: list[str] = []

    def fake_triage(prompt: str, config: LLMConfig, *, system_prompt: str, temperature: float = 0.0) -> str:
        del config, system_prompt, temperature
        seen_prompts.append(prompt)
        payload = json.loads(prompt)
        reviews = []
        first_line = payload["candidates"][0]["sink"]["line"]
        for idx, item in enumerate(payload["candidates"]):
            if idx == 0:
                reviews.append(
                    {
                        "id": item["id"],
                        "decision": "false_positive",
                        "confidence": "high",
                        "reason": f"At line {item['sink']['line']}, raw_query passed to execute is constrained.",
                    }
                )
            elif idx == 1:
                reviews.append(
                    {
                        "id": item["id"],
                        "decision": "false_positive",
                        "confidence": "medium",
                        "reason": f"At line {item['sink']['line']}, blacklist on user_path.",
                    }
                )
            elif idx == 2:
                # Uses CWE-22 digit + stopwords only (no explicit valid line or code symbol)
                reviews.append(
                    {
                        "id": item["id"],
                        "decision": "false_positive",
                        "confidence": "high",
                        "reason": "CWE-22 check on the line is safe.",
                    }
                )
            else:
                # Cross-candidate leakage: cites candidate 0's line & symbol instead of its own
                reviews.append(
                    {
                        "id": item["id"],
                        "decision": "false_positive",
                        "confidence": "high",
                        "reason": f"At line {first_line}, raw_query in sqlite3 execute is safe.",
                    }
                )
        return json.dumps({"reviews": reviews}, ensure_ascii=False)

    monkeypatch.setattr("auditforge.llm_candidates.load_llm_json_response", fake_triage)
    monkeypatch.setenv("TEST_TRIAGE_KEY", "dummy-key")
    kept, triage_diag = triage_candidates_with_llm(
        repo,
        facts,
        cands,
        LLMConfig(
            enabled=True,
            provider="openai-compatible",
            api_key_env="TEST_TRIAGE_KEY",
            discovery_enabled=False,
            triage_enabled=True,
        ),
    )
    assert seen_prompts
    for prompt_text in seen_prompts:
        assert "secret_sqli_case" not in prompt_text
        assert "sqli-00" not in prompt_text
        assert "pathtr-00" not in prompt_text
        assert "expected vulnerable case" not in prompt_text
        assert "<route>" in prompt_text
    assert triage_diag["all_count"] == len(cands)
    assert triage_diag["filtered_count"] == 1
    assert len(kept) == len(cands) - 1
    assert len(triage_diag["all_candidates"]) == len(cands)
    assert len(triage_diag["verified_candidates"]) == len(kept)

    result = run_scan(
        repo,
        tmp_path / "ws",
        verify="none",
        llm_config=LLMConfig(
            enabled=True,
            provider="openai-compatible",
            api_key_env="TEST_TRIAGE_KEY",
            discovery_enabled=False,
            triage_enabled=True,
        ),
    )
    assert len(result.candidates) == len(cands) - 1
    assert result.llm_diagnostics["triage"]["all_count"] == len(cands)
    assert result.llm_diagnostics["triage"]["filtered_count"] == 1
