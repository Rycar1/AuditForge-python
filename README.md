# AuditForge

AuditForge 是一个本地优先的 Python 白盒代码审计平台原型，用于生成可追踪、可验证的 source-to-sink 候选路径。

它不是“让 LLM 读代码后直接写报告”的工具，而是把 AI 审计拆成可落库、可复核、可动态验证的流水线：

- 多语言代码索引与 JS/TS、Java、Go、PHP 语义前端；PHP 支持 Composer/PSR-4、命名空间和依赖注入类型解析，TS 在本地存在 TypeScript Compiler API 时自动升级为 AST 分析
- 统一代码图模型
- Source/Sink/Sanitizer 事实抽取
- 函数内轻量 DFG/CFG、对象别名、跨函数副作用摘要与校验 guard 控制流
- Django/DRF、FastAPI 的请求容器、RawSQL 与授权依赖语义模型；支持安全的 `Depends`/`Security` 输入桥接
- 扫描前项目盘点（代码行数、语言数量、语言占比）
- source-to-sink 候选路径生成
- 多专业 Agent 并行补全候选路径（注入数据流、认证授权、SSRF/XSS），并由本地证据裁判复核排序
- OSV 历史漏洞库确定性匹配与可选 LLM 解释，支持常见 manifest/lockfile、部分传递依赖与 CycloneDX SBOM 导出
- sanitizer 抑制与候选去重
- 安全验证计划与 safe verifier（query、JSON、form、Header、Cookie 和路径参数契约）
- LLM 二次深入验证、严格声明式验证 DSL 与独立并行 runner
- SQLite 证据库
- 中文 Markdown/HTML 报告
- 中文本地 Dashboard
- 候选路径的数据流向图和命中源码片段

当前 MVP 不宣称静态证明。静态候选只进入验证队列；只有在目标运行环境中取得满足漏洞类别门禁的有效运行时证据，结果才会标记为 `confirmed`。新版 deep 流程不会执行 LLM 生成的 Python、Shell 或 Docker 命令；历史 `sandbox_executed` / `sandbox_confirmed` 结果仍可读取，但只按待复核证据展示。

## 安装与开发

AuditForge 需要 Python 3.11 或更高版本。普通静态扫描没有第三方运行时依赖；声明式 deep 验证本身也不要求 Docker/Podman，生产部署建议把 runner 放在独立容器或隔离主机中。

TypeScript 项目若已在仓库中安装兼容 Compiler API 的 TypeScript 5.x，扫描器会自动使用 TypeScript Compiler API，报告中会标记为 `ast`；未安装或 API 不兼容时会明确记录原因并安全回退到现有启发式前端。可在被审计项目根目录执行 `npm install --save-dev typescript@5`，或通过 `AUDITFORGE_TYPESCRIPT_PATH` 指定本机 TypeScript 模块/目录。该可选能力不会下载依赖，也不会修改被审计仓库。

Java 需要完整 JDK（不是仅 JRE），Go 需要本机 Go 工具链。二者可分别使用 JDK compiler tree API 与 Go 标准库 `go/parser` 提取函数、调用、赋值、返回和控制流，结构事实标记为 `ast`；框架 source/sink 模型仍保留 `heuristic` 标识。工具链缺失、语法错误或桥接失败时会按文件安全回退，并把原因写入扫描诊断。

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
auditforge --help
```

安装开发依赖并执行本地检查：

```bash
python -m pip install -e ".[dev]"
python -m ruff check auditforge tests validation
python -m ruff format --check auditforge tests validation
python -m pytest -q
python -m pytest --cov=auditforge --cov-report=term-missing
python -m build
```

仓库中的 `.github/workflows/ci.yml` 会在 push 和 pull request 时分别使用 Python 3.11 和 Python 3.14 执行 Ruff、带分支覆盖率的 pytest（最低覆盖率 70%）以及发行包构建。

## Docker / Compose 部署

仓库提供 `Dockerfile` 和 `compose.yaml`，默认启动名为 `auditforge` 的 Dashboard 服务，并只把 `8765` 映射到宿主机回环地址。先安装 Docker Engine / Docker Desktop 及 Compose 插件，然后为服务设置一个随机且至少 32 字符的管理 token，以及待审计源码的绝对路径。

Linux/macOS：

```bash
export AUDITFORGE_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AUDITFORGE_SOURCE_DIR="$(cd /path/to/target-repository && pwd)"
docker compose up --build -d
docker compose logs -f auditforge
```

Windows PowerShell：

```powershell
$env:AUDITFORGE_ADMIN_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:AUDITFORGE_SOURCE_DIR = (Resolve-Path 'C:\path\to\target-repository').Path
docker compose up --build -d
docker compose logs -f auditforge
```

随后访问 `http://127.0.0.1:8765`，使用 `AUDITFORGE_ADMIN_TOKEN` 登录。首次构建镜像可单独执行 `docker compose build`；停止服务使用 `docker compose down`。若修改了环境变量或宿主机源码目录，使用 `docker compose up -d --force-recreate` 重新创建服务。

默认镜像包含 Java、Go、Node.js 和 TypeScript 工具链，以保留多语言 AST 分析能力。若只审计 Python，设定 `AUDITFORGE_WITH_TOOLCHAINS=0` 后再执行构建，可得到更小、构建更快的 Python-only 镜像；该模式会跳过 Java/Go/JS/TS 的编译器 AST 增强解析。

Compose 会将以下三类数据分开处理：

- `AUDITFORGE_SOURCE_DIR` 会以只读方式挂载到容器内的 `/source`，并作为 Dashboard 的允许源码根目录。它应指向明确授权审计的仓库；不要为了方便把整个用户目录、磁盘根目录或包含凭据的目录挂入容器。
- `auditforge-workspace` 持久卷挂载到 `/workspace`，保存扫描记录、SQLite 证据库、报告、上传文件和 Dashboard 设置。删除容器不会删除这些结果；如需彻底移除数据，确认无保留需求后再显式删除对应 Docker volume。
- `auditforge-cache` 持久卷挂载到 `/var/cache/auditforge`。它能减少重复扫描的耗时，但可能包含从源码派生的元数据，应按与待审计源码相同的敏感级别保护。

叠加 `compose.deep.yaml` 时还会创建 `auditforge-validation-queue`，它只保存短生命周期的声明式任务、heartbeat 和结构化结果；runner 不会因此获得 `/source` 或 `/workspace` 的访问权限。

`AUDITFORGE_ADMIN_TOKEN` 不能留空或使用示例值：服务在容器内监听 `0.0.0.0`，因此 Compose 会显式开启 `AUDITFORGE_ALLOW_REMOTE=1`，同时仅为默认本机地址设置允许的 Host 和 Origin。即使 Compose 默认仅在宿主机 `127.0.0.1` 发布端口，仍必须通过强 token 防止同机其他进程、错误端口转发或未来网络配置变更直接接管 Dashboard。不要将 token 写入提交到版本库的 `.env`、Compose 覆盖文件、镜像层或扫描报告；生产环境还应把 Dashboard 放在 HTTPS 反向代理之后，并按“远程访问 Dashboard”一节配置允许的 Host 和 Origin。

默认允许的浏览器 origin 是 `http://127.0.0.1:8765` 和 `http://localhost:8765`。如在 Compose 覆盖文件中修改宿主机端口、主机名或通过反向代理发布服务，必须同步设置精确的 `AUDITFORGE_ALLOWED_ORIGINS`，并更新 `AUDITFORGE_ALLOWED_HOSTS`；例如改为 `http://127.0.0.1:9000` 时，旧的 `:8765` origin 不会通过浏览器请求校验。

### 容器与 deep 验证边界

Compose **永远不需要挂载**宿主机 Docker socket（例如 `/var/run/docker.sock`）。主 Dashboard 只负责校验并写入声明式任务；独立 `validation-runner` 只通过专用队列卷接收已经规范化的 HTTP 计划。runner 不挂载源码、工作区或 Docker socket，也不接受脚本、Shell、Dockerfile、任意凭据和任意跨 origin URL。

启用隔离 runner：

```bash
docker compose -f compose.yaml -f compose.deep.yaml up --build -d
docker compose -f compose.yaml -f compose.deep.yaml logs -f auditforge validation-runner
```

`compose.deep.yaml` 为 runner 配置非 root、只读根文件系统、丢弃 capability、PID/CPU/内存限制和 `no-new-privileges`。如果待验证服务运行在宿主机，容器内的目标地址应使用 `http://host.docker.internal:<port>`，不要填写容器自身的 `127.0.0.1`。runner 当前只支持同源、禁重定向、限长响应的 HTTP 声明式步骤；Playwright 与 OAST 已保留受控扩展类型，但在未配置可信 provider 时会明确返回 `unsupported/blocked`。

## 快速开始

```bash
python -m auditforge scan --repo /path/to/repo --out ./workspace
python -m auditforge serve --workspace ./workspace --port 8765
```

启动 WebUI 后打开 `http://127.0.0.1:8765`，可以直接在浏览器里：

- 从侧栏进入“概况总览”“新建扫描”“扫描历史”“运行日志”和“设置”
- 在总览页查看风险队列、分析模块状态与最近扫描
- 上传 ZIP 代码包，或在配置仓库根目录白名单后填写本地路径
- 自定义扫描名称、验证模式、目标 URL、是否启用 LLM 候选补全和依赖风险扫描
- 点击“开始扫描”生成独立扫描记录，并先展示项目盘点
- 在任务证据工作区浏览紧凑漏洞列表，点击单条记录后通过右侧详情抽屉复核数据流路径、源码片段、运行证据与人工处置状态
- 在“扫描历史”里进入每次扫描的候选详情、HTML 报告、Markdown 报告或证据导出

### Dashboard 管理 token

受保护的 Dashboard 页面和 API 都需要管理 token。默认监听回环地址时，如果没有设置 `AUDITFORGE_ADMIN_TOKEN`，服务会在每次启动时生成随机 token；无论 token 是生成的还是通过环境变量提供的，都会写入：

```text
<workspace>/.auditforge_admin_token.json
```

打开 Dashboard 后输入该 JSON 文件中的 `token`。登录表单通过同源 `POST /api/login` 提交 token，token 不会进入 URL、浏览器历史或访问日志；成功后浏览器只保存 `HttpOnly`、`SameSite=Strict` 的短期会话 cookie。这个文件属于敏感凭据，不应提交到版本库、打包进扫描导出或分享给其他用户。也可以预先设置 `AUDITFORGE_ADMIN_TOKEN` 使用固定 token。

### Dashboard 本地仓库白名单

Dashboard 默认不允许读取任意本地路径，只允许上传 ZIP。需要从 WebUI 扫描本地仓库时，显式配置一个或多个允许的根目录：

```bash
auditforge serve \
  --workspace ./workspace \
  --allowed-repo-root /srv/source \
  --allowed-repo-root /srv/other-source
```

也可以设置 `AUDITFORGE_ALLOWED_REPO_ROOTS`。多个路径使用操作系统的路径分隔符：Windows 使用分号，Linux/macOS 使用冒号。命令行出现 `--allowed-repo-root` 时，以命令行列表为准。解析后的仓库必须位于某个允许根目录内；UNC 路径、Windows 设备路径和通过链接逃逸根目录的路径会被拒绝。

### 远程访问 Dashboard

内置 Web 服务只提供 HTTP，不负责 TLS。任何远程访问都必须放在 HTTPS 反向代理之后，并通过防火墙阻止公网直接访问后端端口。反向代理应保留正确的 `Host`，并让浏览器请求使用外部 HTTPS origin。

若必须绑定非回环地址，还需要同时满足以下条件：

- `AUDITFORGE_ALLOW_REMOTE=1`
- `AUDITFORGE_ADMIN_TOKEN` 至少 32 个字符
- `AUDITFORGE_ALLOWED_HOSTS`：逗号分隔的允许 Host，例如 `audit.example.com`
- `AUDITFORGE_ALLOWED_ORIGINS`：逗号分隔的完整 origin，例如 `https://audit.example.com`

```bash
export AUDITFORGE_ALLOW_REMOTE=1
export AUDITFORGE_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AUDITFORGE_ALLOWED_HOSTS='audit.example.com'
export AUDITFORGE_ALLOWED_ORIGINS='https://audit.example.com'
auditforge serve --workspace ./workspace --host 0.0.0.0 --port 8765
```

非回环模式不会把管理 token 写入工作区，管理员必须通过 `AUDITFORGE_ADMIN_TOKEN` 安全分发。以上设置不会替代 HTTPS 反向代理。

## 日志

CLI 默认向控制台输出 INFO 及以上日志，也可以同时写入轮转文件或改为 JSON Lines：

```bash
auditforge scan \
  --repo /path/to/repo \
  --out ./workspace \
  --log-level DEBUG \
  --log-file ./logs/auditforge.log \
  --log-json
```

| CLI 参数 | 环境变量 | 行为 |
| --- | --- | --- |
| `--log-level` | `AUDITFORGE_LOG_LEVEL` | `DEBUG`、`INFO`、`WARNING`、`ERROR` 或 `CRITICAL`；默认 `INFO` |
| `--log-file` | `AUDITFORGE_LOG_FILE` | 额外写入日志文件；未配置时只输出到控制台 |
| `--log-json` | `AUDITFORGE_LOG_FORMAT=json` | 控制台和文件均使用每行一个 JSON object 的结构化日志 |

日志文件默认在 5 MiB 时轮转并保留 3 个备份。日志层会遮蔽常见 API key、Bearer token、密码、cookie、session、URL userinfo 等敏感值，但不应依赖自动遮蔽来记录任意秘密。

Dashboard 的“运行日志”页会增量读取服务进程最近 2,000 条日志，可按级别和文本筛选，也可以暂停自动滚动或清空当前浏览器视图。这个页面和 `/api/logs` 都受管理会话保护；服务端返回前会再次遮蔽敏感字段与异常堆栈。清屏不会删除轮转日志文件，也不会影响其他浏览器会话。

## 验证模式

| 模式 | 行为 | 使用边界 |
| --- | --- | --- |
| `none` | 只生成静态与可选 LLM 候选，不发验证请求 | 默认模式 |
| `safe` | 仅对 GET/HEAD 类路由执行有界只读探测；只允许 HTTP(S)、同源路由，禁止重定向、跨 origin 和 metadata/link-local 目标 | 自有或明确授权的运行目标 |
| `stateful` | 保留 safe 的网络边界，但允许受控 POST，并可能创建测试数据 | 仅限明确授权、可丢弃且可清理的隔离靶场 |
| `deep` | 让 LLM 生成严格声明式计划，经本地 schema/同源/方法/大小门禁后交给独立 runner | 需要目标 URL；证据不足时保守进入人工复核 |
| `safe+deep` | 先执行内置 safe verifier，再并行执行声明式 runner 计划 | 合并两条相互独立的运行时证据链 |
| `stateful+deep` | 为未来可信 cleanup provider 保留；当前 runner 会拒绝没有可验证清理能力的写请求 | 仅限明确授权的可丢弃靶场 |

safe 和 stateful 每个候选最多发送两次受控请求；两者都需要通过 `--target-url` 指定只包含 scheme、host 和可选端口的目标地址。safe 示例：

```bash
python -m auditforge scan --repo /path/to/repo --target-url http://localhost:3000 --verify safe --out ./workspace
```

stateful 示例：

```bash
python -m auditforge scan --repo /path/to/repo --target-url http://localhost:3000 --verify stateful --out ./workspace
```

如果希望让 LLM 为候选生成可执行的运行时验证计划，可以启用 deep 模式。推荐启动独立队列 runner；两个进程只共享队列目录：

```powershell
$env:AUDITFORGE_LLM_API_KEY = '<your-api-key>'
$env:AUDITFORGE_VALIDATION_RUNNER_MODE = 'queue'
$env:AUDITFORGE_VALIDATION_QUEUE = (New-Item -ItemType Directory -Force .\validation-queue).FullName

# 终端 1：独立 runner
python -m auditforge validation-runner --queue $env:AUDITFORGE_VALIDATION_QUEUE --concurrency 4

# 终端 2：扫描进程
python -m auditforge scan --repo C:\path\to\repo --target-url http://127.0.0.1:3000 --out .\workspace --verify deep
```

开发和单元测试可设置 `AUDITFORGE_VALIDATION_RUNNER_MODE=inline` 在当前进程执行同一套 DSL，但正式使用应选 `queue`，把执行边界与 Dashboard/扫描 worker 分开。

启用 LLM 候选补全：

```bash
set AUDITFORGE_LLM_API_KEY=<your-api-key>
python -m auditforge scan --repo /path/to/repo --out ./workspace --llm-candidates
```

启用依赖历史漏洞扫描。精确版本会直接查询 OSV；配置 LLM 时再补充中文利用条件解释：

```bash
python -m auditforge scan --repo /path/to/repo --out ./workspace --dependency-scan
```

OSV 查询不需要 API key；只有同时启用 LLM 解释时才需要配置模型连接。

也可以使用 OpenAI-compatible 服务：

```bash
python -m auditforge scan \
  --repo /path/to/repo \
  --out ./workspace \
  --llm-candidates \
  --llm-provider openai-compatible \
  --llm-base-url http://127.0.0.1:11434/v1 \
  --llm-model <model-name> \
  --llm-concurrency 3 \
  --llm-api-key-env AUDITFORGE_LLM_API_KEY
```

远程 OpenAI-compatible 地址必须使用 HTTPS；只有回环地址允许使用 HTTP。base URL 不能包含用户凭据、查询参数或 fragment，LLM 请求也不会跟随重定向。

LLM 候选补全不会直接确认漏洞。扫描会按模块、入口和 sink 分片，由注入数据流、认证授权、SSRF/XSS 三类专业 Agent 并行审计；每个分片会带上跨文件连通调用子图、导入、装饰器与有限的配置上下文。候选先经过 JSON/源码锚点校验，再由本地证据裁判检查 source-to-sink 步骤是否闭合、是否存在已建模的 sanitizer/guard，按证据质量排序后才合并入队。deep 模式也不能凭 LLM verdict 确认漏洞：只有受控 runner 的真实响应和类别门禁同时满足时才可能升级为 `confirmed`。
LLM 首轮完成后会根据覆盖地图自动挑选未匹配危险 sink、未解析的内部调用、未绑定路由、parser fallback 和实际未进入 prompt 的安全锚点，执行一次有界专项补扫。失败 Agent 只自动重试一次；补扫最多 6 个 scope，结果会写入 `llm_diagnostics.json` 和 `analysis_coverage.json`。覆盖地图中的“盲区”是需要继续审计的证据缺口，不会被误显示为漏洞。
依赖扫描首先用“生态 + 包名 + 精确版本”查询 OSV 历史漏洞库，保存 OSV/GHSA/CVE、受影响区间、修复版本和引用；LLM 只负责解释。支持 requirements/pyproject/uv/poetry/Pipfile、package/package-lock/npm-shrinkwrap/yarn/pnpm、pom、go.mod/go.sum、Cargo、Gem、Composer 和 NuGet 锁文件。扫描产物会同时导出带 advisory 关联的 CycloneDX 1.5 SBOM。没有 lockfile 的范围版本会标记为未解析，而不会猜测已安装版本。
LLM 并发通过 `--llm-concurrency` 调整；runner 并发通过 `auditforge validation-runner --concurrency` 调整。生成计划和执行计划使用两级独立并发，遇到模型限流或目标服务容量不足时可分别调低。

声明式 runner 可通过环境变量调整：

- `AUDITFORGE_VALIDATION_RUNNER_MODE`：`disabled`、`inline` 或 `queue`；生产推荐 `queue`。
- `AUDITFORGE_VALIDATION_QUEUE`：Dashboard/扫描 worker 与独立 runner 共享的队列目录。
- `AUDITFORGE_VALIDATION_TIMEOUT`：等待 runner 结果的总超时秒数，限制为 5–600 秒。
- `AUDITFORGE_VALIDATION_CONCURRENCY`：`compose.deep.yaml` 中 runner 的并行任务数，默认 2，限制为 1–12。
- `AUDITFORGE_VALIDATION_RUNNER_ID`：可选 runner 实例标识，仅用于 heartbeat/诊断，不是凭据。

LLM 输出采用 fail-closed 策略：

- 污点候选必须返回根字段 `candidates`，且每条候选必须包含 `vulnClass`、`source`、`sink`、`confidence`、`staticEvidence`、`verificationHint` 等字段。
- 依赖扫描必须返回根字段 `findings`，且包名必须来自解析出的依赖清单。
- 二次验证必须返回 `verdict`、`confidence`、`reason`、`validationPlans`；未知字段、绝对/跨 origin URL、危险 Header、metadata/link-local 引用、超限步骤或断言都会被拒绝。旧 `sandboxTests` 结果只保留历史兼容，不再作为新执行入口。
- 自定义提示词会被保留，但运行时仍会强制追加不可变 JSON 输出契约；服务端再做字段、类型、枚举值、源码锚点和安全策略校验。

也可以在 Dashboard 的“设置”页保存 OpenAI-compatible API、模型和 API key，然后让扫描命令读取工作区设置：

```bash
python -m auditforge scan --repo /path/to/repo --out ./workspace --use-workspace-settings
```

非敏感工作区设置保存在 `auditforge_settings.json`，其中不写入明文 API key。API key 单独保存在 `.auditforge_secrets.json` 并绑定录入时的 LLM endpoint：Windows 使用当前用户的 DPAPI 加密，其他平台使用仅属主可读的受限文件作为兼容回退。修改 endpoint 不会自动把旧 key 发送给新地址。`/api/settings`、Dashboard 页面和报告只显示遮蔽后的 key；这两个本地配置文件都不应提交或分享。

## 输出文件

- `auditforge.db`：SQLite 证据库
- `auditforge_runs.json`：WebUI 扫描历史索引
- `runs/<run-id>/`：WebUI 每次扫描的独立工作区
- `uploads/`、`uploaded_repos/`：WebUI 上传 zip 及解压后的代码目录
- `.auditforge_admin_token.json`：仅回环监听时生成的 Dashboard 管理 token（敏感文件）
- `code_graph.json`：轻量图索引；完整事实保存在压缩的 `code_graph/facts.json.gz`
- `code_graph/`：按节点/边分块并按源码文件切片的 gzip 图证据；Dashboard 通过分页 API 按需读取，不再把完整图复制进 SQLite
- `scan_metadata.json`：扫描参数、统计信息和分析诊断摘要
- `analysis_coverage.json`：分析置信分、parser/调用解析/source-sink/LLM 上下文覆盖，以及按优先级排序的盲区和专项补扫结果
- `scan_complete.json`：所有结果、数据库和报告成功写入后最后发布的完成标记
- `project_inventory.json`：扫描前项目盘点，包括代码总行数、语言数量、统计文件和语言占比
- `trace_candidates.json`：source-to-sink 候选路径
- `verification_plans.json`：受控复现计划
- `verification_runner_plans.json`：通过严格校验后实际提交给独立 runner 的声明式计划
- `verification_results.json`：safe verifier、声明式 runner 和历史 deep 沙箱验证结果
- `llm_diagnostics.json`：LLM 调用、接收、拒绝和错误诊断
- `dependency_inventory.json`：解析出的依赖清单和依赖版本
- `dependency_findings.json`：OSV/GHSA/CVE 历史库匹配及 LLM 解释后的依赖风险
- `sbom.cdx.json`：带精确组件 purl 和 advisory 关联的 CycloneDX 1.5 SBOM
- `result_sections.json`：按依赖风险、已确认漏洞、沙箱执行待复核、候选漏洞和验证归档分区后的结果索引
- `result_sections/`：每个结果分区的独立 JSON 文件，便于后续接入归档、导出或外部系统
- `auditforge_settings.json`：可选的非敏感 LLM endpoint、模型和提示词设置
- `.auditforge_secrets.json`：与 LLM endpoint 绑定的本地 API key 存储（敏感文件）
- `report.md`：中文 Markdown 报告
- `report.html`：中文 HTML 报告

## 架构

AuditForge 由几个小模块组成：

1. `project_inventory`：扫描前统计代码总行数、语言数量、统计文件和语言占比。
2. `scanner` / `python_analysis` / `framework_models` / `java_framework` / `php_symbols` / `javascript_analysis` / `typescript_compiler_bridge` / `native_ast_bridge` / `java_go_analysis` / `php_analysis`：语言识别与统一事实抽取。Python 使用标准库 AST，并叠加 Django/DRF、FastAPI 的可版本化框架模型；对象别名、参数对象副作用与 FastAPI 依赖输入会跨调用链传播。TS 在本地可解析 TypeScript Compiler API 时走编译器 AST；Java/Go 在本机工具链可用时用各自原生解析器抽取结构事实。Java 额外解析 Spring 字段/构造器注入、接口实现及 MyBatis XML/注解中的动态 `${...}` SQL（`#{...}` 参数绑定不报为注入）。PHP 聚合多行逻辑语句，解析 namespace、grouped `use`、Composer PSR-4、typed property、构造器提升属性、Laravel 容器绑定和跨文件 receiver 类型；框架模型覆盖 Laravel、Symfony、Slim/PSR-7、Doctrine、WordPress、Guzzle/Laravel HTTP 与 Symfony Process。依赖缺失时仍保持 dependency-free，并明确标记为 `heuristic`，不会伪装成 AST 精度。
3. `graph` / `graph_artifacts`：生成统一代码图，节点包括 File、Function、Route、Source、Sink、Sanitizer、CallSite、DataFlow、ControlFlow；产物压缩分块持久化，提供按文件、节点和边的分页读取。
4. `candidates`：生成 source-to-sink 候选路径，处理 sanitizer 抑制和候选去重。
5. `llm_candidates`：按模块/入口/sink 切片，由多个专业 Agent 并行审计；每个任务保留受限的跨文件调用闭包和结构上下文，解析 JSON 候选后做锚点校验、独立本地证据门禁、质量排序、fingerprint 去重和来源标记。
6. `audit_coverage`：汇总文件解析、内部调用解析、未匹配 source/sink、框架入口、LLM 实际上下文和失败任务；首轮 Agent 成功后最多执行一轮、最多 6 个高优先级盲区专项补扫。分析置信分只表示可观察覆盖，不代表漏洞检出率或漏报率。
7. `dependency_scan`：解析 manifest/lockfile，以精确版本查询 OSV 历史漏洞库，并可选调用 LLM 解释利用条件。
8. `verification`：生成复现计划，并执行有界、非破坏性的 safe 验证；会从 Source 与 Route 事实构造 query、JSON、form、Header、Cookie 与路径参数请求契约，拒绝危险方法和 Header。
9. `deep_verification` / `validation_dsl` / `validation_runner`：调用 LLM 生成声明式计划，严格规范化后交给独立并行 runner，并把步骤、断言和脱敏响应保存为结构化证据。
10. `store`：把扫描结果、候选和验证结果写入 SQLite。
11. `report`：生成中文 Markdown/HTML 报告，并区分“已确认漏洞”“沙箱执行待复核”“静态候选”和“依赖风险候选”。
12. `server`：提供中文本地审计工作台和 JSON API。
13. `snippets`：按代码锚点回读真实源码，为候选路径展示上下文和高亮命中行。

## 安全模型

safe verifier 只做有界、非破坏性检查：

- GET/HEAD 可达性探测
- XSS 候选的无害标记反射检查
- 基于真实参数名的无害探测，例如 `q`、`name`、`id`、`msg`
- 不执行破坏性 HTTP 方法
- 不做暴力破解
- 不访问 metadata 或 link-local SSRF 目标
- 不执行命令类 payload

safe 不会退化为 POST 探测。需要数据变更的候选会标记为需要人工验证；只有显式选择 stateful 时才允许受控 POST，且该模式只能用于可丢弃、可清理的隔离靶场。需要真实凭证、复杂状态切换、回连监听或 exploit payload 的候选仍需人工验证。

deep verifier 额外执行以下限制：

- LLM 只能输出 JSON 结构化结论和声明式步骤，不能提供可执行代码、Shell、Docker 命令、任意模板求值或凭据。
- target origin 由用户的 `target_url` 注入；计划只能使用同源 HTTP(S)，禁止重定向、代理继承、metadata/link-local、危险 Header 和超限请求/响应。
- 默认只允许 GET/HEAD。写方法即使在 stateful 模式下，也必须存在可信 cleanup provider；当前内置 runner 会保守拒绝。
- Dashboard 与 runner 只共享窄队列；runner 不挂载源码、工作区或 Docker socket，并维护 heartbeat、任务超时、陈旧任务恢复和 job/plan identity 校验。
- 通用 marker 或模型判断不能直接确认漏洞。认证授权需要未来双身份对比，SSRF 需要 OAST，XSS 需要浏览器上下文证据；能力缺失时返回 `blocked` / `needs_manual_review`。
- 历史 `sandbox_executed` / `sandbox_confirmed` 仍可读取，但不属于已确认漏洞。

## 后续演进方向

当前版本使用无第三方依赖的确定性启发式分析，便于快速运行和测试。后续可以在现有接口后面接入：

- Tree-sitter AST 深度解析
- 框架特定路由/ORM/模板分析器
- LLM reviewer，用于解释动态分发、框架魔法和业务权限语义
- Playwright 浏览器验证
- SSRF 回连监听器
- 更细粒度的跨函数 DFG/taint trace
