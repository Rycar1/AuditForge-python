# Python Vulnerable Lab

这是一个用于测试 AuditForge 的本地 Flask 漏洞靶场。代码故意包含多类白盒审计候选路径，请只在本机测试环境运行。

## 包含的漏洞类型

- SQL 注入：`/search?q=...`
- 反射型 XSS：`/hello?name=...`
- SSRF：`/fetch?url=...`
- 命令注入：`/ping?host=...`
- 路径穿越：`/download?file=...`
- 不安全反序列化：`/import-profile`
- 模板注入：`/render?template=...`
- 越权/角色绕过：`/admin/report?role=...`
- 弱登录逻辑：`/login`

## 启动

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py
```

默认监听 `http://127.0.0.1:5005`。

## 推荐扫描路径

在 AuditForge WebUI 的“新建扫描”里选择本地路径：

```text
<repository-root>\fixtures\python_vuln_lab
```

如果要做动态验证，请把目标 URL 填为：

```text
http://127.0.0.1:5005
```
