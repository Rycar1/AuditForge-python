from __future__ import annotations

import argparse
import signal
import sys
import threading
from dataclasses import replace
from pathlib import Path

from .engine import run_scan
from .llm_candidates import DEFAULT_BASE_URL, DEFAULT_MODEL, LLMConfig
from .logging_config import configure_logging, contextual_logger
from .server import serve_workspace
from .settings import llm_config_from_settings, load_workspace_settings, sandbox_concurrency_from_settings
from .user_errors import classify_error, format_cli_error, new_reference
from .validation_runner import run_validation_worker
from .web_security import WebSecurityConfig, is_unc_or_device_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="auditforge", description="本地优先的白盒代码审计平台")
    add_logging_arguments(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="扫描代码仓库")
    add_logging_arguments(scan, suppress_defaults=True)
    scan.add_argument("--repo", required=True, help="待扫描仓库路径")
    scan.add_argument("--out", required=True, help="工作区输出目录")
    scan.add_argument("--target-url", help="可选运行目标地址，用于 safe 验证")
    scan.add_argument(
        "--verify",
        choices=["none", "safe", "stateful", "deep", "safe+deep", "stateful+deep"],
        default="none",
        help="验证模式；stateful 仅用于明确授权、可丢弃的隔离靶场",
    )
    scan.add_argument("--dependency-scan", action="store_true", help="启用 OSV 历史漏洞库匹配和可选 LLM 依赖解释")
    scan.add_argument("--use-workspace-settings", action="store_true", help="读取输出工作区保存的 LLM 设置")
    scan.add_argument("--llm-candidates", action="store_true", help="启用 LLM 候选路径补全")
    scan.add_argument("--llm-triage", action="store_true", help="启用 LLM 候选误报复核")
    scan.add_argument("--llm-timeout", type=int, default=60, help="单次 LLM 请求超时秒数")
    scan.add_argument(
        "--llm-provider",
        choices=["openai-compatible", "fixture"],
        default="openai-compatible",
        help="LLM provider；fixture 用于离线测试",
    )
    scan.add_argument("--llm-model", default=DEFAULT_MODEL, help="LLM 模型名称")
    scan.add_argument("--llm-base-url", default=DEFAULT_BASE_URL, help="OpenAI-compatible API base URL")
    scan.add_argument("--llm-api-key-env", default="AUDITFORGE_LLM_API_KEY", help="读取 API key 的环境变量名")
    scan.add_argument("--llm-response-file", help="fixture provider 的 JSON 响应文件")
    scan.add_argument("--llm-max-candidates", type=int, default=200, help="每次最多接收的 LLM 候选数")
    scan.add_argument(
        "--llm-concurrency",
        type=int,
        default=3,
        help="LLM 多 Agent 候选审计、依赖拆分和并行沙箱验证的并发线程数",
    )
    scan.add_argument(
        "--validation-concurrency",
        "--runner-concurrency",
        "--sandbox-concurrency",
        dest="sandbox_concurrency",
        type=int,
        help="声明式验证计划的并行提交数；--sandbox-concurrency 仅作为旧名称兼容",
    )

    serve = sub.add_parser("serve", help="启动本地 Dashboard")
    add_logging_arguments(serve, suppress_defaults=True)
    serve.add_argument("--workspace", required=True, help="scan 生成的工作区")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument(
        "--allowed-repo-root",
        action="append",
        default=[],
        help="允许 Dashboard 扫描本地路径的根目录，可重复；未配置时仅允许上传 zip",
    )

    validation_runner = sub.add_parser("validation-runner", help="启动独立的声明式验证 runner")
    add_logging_arguments(validation_runner, suppress_defaults=True)
    validation_runner.add_argument("--queue", required=True, help="与 Dashboard 共享的验证队列目录")
    validation_runner.add_argument("--concurrency", type=int, default=2, help="并行执行的验证任务数（1-12）")
    validation_runner.add_argument("--poll-interval", type=float, default=0.25, help="队列轮询间隔秒数")
    validation_runner.add_argument("--once", action="store_true", help="最多处理一个任务后退出，便于健康检查和测试")

    args = parser.parse_args(argv)
    try:
        logger = configure_logging(
            level=getattr(args, "log_level", None),
            log_file=getattr(args, "log_file", None),
            json_format=True if getattr(args, "log_json", False) else None,
        )
    except Exception as exc:  # noqa: BLE001 - logging setup is part of the command boundary
        public_error = classify_error(exc, context="configuration", reference=new_reference("AFC"))
        print(format_cli_error(public_error), file=sys.stderr)
        return 1
    if args.command == "validation-runner":
        queue_path = Path(args.queue).expanduser().resolve()
        runner_logger = contextual_logger(logger, command="validation-runner", queue=str(queue_path))
        stop_event = threading.Event()
        interrupted = False

        def request_stop(_signum, _frame) -> None:  # noqa: ANN001 - signal callback signature
            nonlocal interrupted
            interrupted = True
            stop_event.set()

        previous_handlers = {}
        for signal_name in ("SIGINT", "SIGTERM"):
            signum = getattr(signal, signal_name, None)
            if signum is not None:
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, request_stop)
        runner_logger.info(
            "validation runner started",
            extra={"event": "validation_runner.started", "concurrency": args.concurrency},
        )
        try:
            processed = run_validation_worker(
                queue_path,
                concurrency=args.concurrency,
                poll_interval=args.poll_interval,
                once=args.once,
                stop_event=stop_event,
            )
        except Exception as exc:  # noqa: BLE001 - CLI service boundary
            reference = new_reference("AFC")
            public_error = classify_error(exc, context="validation_runner", reference=reference)
            runner_logger.exception(
                "validation runner failed",
                extra={"event": "validation_runner.failed", "error_type": type(exc).__name__, "diagnostic_id": reference},
            )
            print(format_cli_error(public_error), file=sys.stderr)
            return 1
        finally:
            for signum, previous in previous_handlers.items():
                signal.signal(signum, previous)
        runner_logger.info(
            "validation runner stopped",
            extra={"event": "validation_runner.stopped", "processed": processed},
        )
        return 130 if interrupted else 0
    if args.command == "scan":
        repo_path = Path(args.repo).expanduser().resolve()
        if not repo_path.exists() or not repo_path.is_dir():
            parser.error(f"待扫描仓库不存在或不是目录：{repo_path}")
        out_path = Path(args.out)
        scan_logger = contextual_logger(logger, command="scan", repo=str(repo_path), workspace=str(out_path.resolve()))
        scan_logger.info("scan started", extra={"event": "scan.started"})
        error_context = "configuration"
        try:
            llm_config = build_llm_config(args, out_path, profile="taint")
            deep_llm_config = build_llm_config(args, out_path, profile="deep") if "deep" in args.verify else None
            dependency_llm_config = build_llm_config(args, out_path, profile="dependency") if args.dependency_scan else None
            sandbox_concurrency = args.sandbox_concurrency
            if sandbox_concurrency is None and args.use_workspace_settings:
                sandbox_concurrency = sandbox_concurrency_from_settings(load_workspace_settings(out_path))
            error_context = "scan"
            result = run_scan(
                repo_path,
                out_path,
                args.target_url,
                args.verify,
                llm_config,
                deep_llm_config,
                dependency_scan=args.dependency_scan,
                dependency_llm_config=dependency_llm_config,
                sandbox_concurrency=sandbox_concurrency,
            )
        except Exception as exc:  # noqa: BLE001 - CLI must return a useful non-zero status
            reference = new_reference("AFC")
            public_error = classify_error(exc, context=error_context, reference=reference)
            scan_logger.exception(
                "scan failed",
                extra={"event": "scan.failed", "error_type": type(exc).__name__, "diagnostic_id": reference},
            )
            print(format_cli_error(public_error), file=sys.stderr)
            return 1
        print("AuditForge 扫描完成")
        print(f"  工作区：{out_path.resolve()}")
        print(f"  候选路径：{len(result.candidates)}")
        if llm_config.enabled:
            print(f"  LLM补全：{result.llm_diagnostics.get('accepted', 0)}")
            if result.llm_diagnostics.get("error"):
                warning = classify_error(RuntimeError(str(result.llm_diagnostics["error"])), context="llm")
                print(f"  LLM提示：{warning.message} {warning.action}", file=sys.stderr)
        if args.dependency_scan:
            print(f"  依赖风险候选：{len(result.dependency_findings)}")
            if result.dependency_diagnostics.get("error"):
                print("  依赖扫描提示：部分依赖数据源未完成，请查看日志确认覆盖范围。", file=sys.stderr)
        print(f"  报告：{out_path.resolve() / 'report.html'}")
        scan_logger.info(
            "scan completed",
            extra={"event": "scan.completed", "candidates": len(result.candidates), "stats": result.stats()},
        )
        return 0
    if args.command == "serve":
        serve_logger = contextual_logger(logger, command="serve", workspace=str(Path(args.workspace).resolve()))
        serve_logger.info(
            "dashboard starting",
            extra={"event": "server.starting", "host": args.host, "port": args.port},
        )
        try:
            workspace = Path(args.workspace).expanduser().resolve()
            security = WebSecurityConfig.from_environment(workspace, args.host)
            if args.allowed_repo_root:
                roots: list[Path] = []
                for value in args.allowed_repo_root:
                    if is_unc_or_device_path(value):
                        parser.error("--allowed-repo-root 不允许 UNC 或 Windows 设备路径")
                    root = Path(value).expanduser().resolve()
                    if not root.exists() or not root.is_dir():
                        parser.error(f"允许的仓库根目录不存在或不是目录：{root}")
                    roots.append(root)
                security = replace(security, allowed_repo_roots=tuple(dict.fromkeys(roots)))
            serve_workspace(workspace, args.host, args.port, security=security)
        except KeyboardInterrupt:
            serve_logger.info("dashboard stopped by user", extra={"event": "server.stopped"})
            return 130
        except Exception as exc:  # noqa: BLE001 - CLI service boundary
            reference = new_reference("AFC")
            public_error = classify_error(exc, context="server_start", reference=reference)
            serve_logger.exception(
                "dashboard failed to start",
                extra={"event": "server.start_failed", "error_type": type(exc).__name__, "diagnostic_id": reference},
            )
            print(format_cli_error(public_error), file=sys.stderr)
            return 1
        return 0
    return 2


def add_logging_arguments(parser: argparse.ArgumentParser, *, suppress_defaults: bool = False) -> None:
    default = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=default,
        help="日志级别；默认读取 AUDITFORGE_LOG_LEVEL 或使用 INFO",
    )
    parser.add_argument(
        "--log-file",
        default=default,
        help="可选轮转日志文件；默认读取 AUDITFORGE_LOG_FILE",
    )
    parser.add_argument(
        "--log-json",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="使用 JSON Lines 日志；也可设置 AUDITFORGE_LOG_FORMAT=json",
    )


def build_llm_config(args: argparse.Namespace, workspace: Path, profile: str = "taint") -> LLMConfig:
    if args.use_workspace_settings:
        config = llm_config_from_settings(load_workspace_settings(workspace), profile=profile)
        if args.llm_response_file:
            return LLMConfig(
                enabled=config.enabled,
                provider=config.provider,
                model=config.model,
                base_url=config.base_url,
                api_key=config.api_key,
                api_key_env=config.api_key_env,
                response_file=args.llm_response_file,
                timeout_seconds=config.timeout_seconds,
                max_prompt_chars=config.max_prompt_chars,
                max_candidates=config.max_candidates,
                concurrency=config.concurrency,
                system_prompt=config.system_prompt,
                user_prompt=config.user_prompt,
            )
        return config
    return LLMConfig(
        enabled=llm_profile_requested(args, profile),
        provider=args.llm_provider,
        model=args.llm_model,
        base_url=args.llm_base_url,
        api_key_env=args.llm_api_key_env,
        response_file=args.llm_response_file,
        timeout_seconds=max(10, int(getattr(args, "llm_timeout", 60))),
        max_candidates=args.llm_max_candidates,
        concurrency=max(1, min(12, args.llm_concurrency)),
        discovery_enabled=bool(getattr(args, "llm_candidates", False)) if profile == "taint" else True,
        triage_enabled=bool(getattr(args, "llm_triage", False)) if profile == "taint" else False,
    )


def llm_profile_requested(args: argparse.Namespace, profile: str) -> bool:
    if profile == "taint":
        return bool(getattr(args, "llm_candidates", False) or getattr(args, "llm_triage", False))
    if profile == "deep":
        return "deep" in getattr(args, "verify", "none")
    if profile == "dependency":
        return bool(getattr(args, "dependency_scan", False))
    raise ValueError(f"unknown LLM profile: {profile}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
