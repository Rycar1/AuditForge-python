from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from .models import Confidence, VulnClass


@dataclass(frozen=True)
class SourceRule:
    kind: str
    pattern: Pattern[str]
    confidence: Confidence


@dataclass(frozen=True)
class SinkRule:
    kind: str
    vuln_class: VulnClass
    pattern: Pattern[str]
    confidence: Confidence


@dataclass(frozen=True)
class SanitizerRule:
    kind: str
    pattern: Pattern[str]
    confidence: Confidence


def rx(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


SOURCE_RULES: tuple[SourceRule, ...] = (
    SourceRule("http_query", rx(r"\b(req|request|ctx|c)\.(query|args|values|URL\.Query|getParameter)\b|getParameter\s*\("), "high"),
    SourceRule(
        "http_body",
        rx(
            r"\b(req|request|ctx|c)\.(body|form|json|data|POST|getInputStream|getReader|get_data|get_json)\b|\bget_data\s*\(|\bget_json\s*\("
        ),
        "high",
    ),
    SourceRule("http_path", rx(r"\b(req|request|ctx|c)\.(params|param|path_params|PathValue)\b"), "high"),
    SourceRule("http_header", rx(r"\b(req|request|ctx|c)\.(headers|header|getHeader)\b|getHeader\s*\("), "medium"),
    SourceRule("cookie", rx(r"\b(cookies?|Cookie)\b|(?<!\.)\bsession\s*(?:\[|\.get\s*\(|\.pop\s*\()"), "medium"),
    SourceRule("graphql_args", rx(r"\b(graphql|gql|resolver|variables)\b"), "medium"),
    SourceRule("websocket_message", rx(r"\b(socket|websocket|ws)\.(on|message|recv|receive)\b"), "medium"),
    SourceRule("file_upload", rx(r"\b(upload|multipart|formidable|multer|Part|IFormFile|UploadedFile)\b"), "medium"),
)

SINK_RULES: tuple[SinkRule, ...] = (
    SinkRule("raw_sql", "injection", rx(r"\b(query|execute|executeQuery|exec|raw|execSQL|createQuery|QueryRow)\s*\("), "medium"),
    SinkRule(
        "command_execution",
        "injection",
        rx(
            r"\b(child_process\.(exec|execFile|spawn)|execFile|spawn|Runtime\.getRuntime\(\)\.exec|"
            r"subprocess\.(run|Popen|call|check_output|check_call)|os\.system|ProcessBuilder)\s*\("
        ),
        "high",
    ),
    SinkRule(
        "file_path",
        "injection",
        rx(r"\b(readFile|writeFile|createReadStream|open|fopen|send_file|FileInputStream|os\.Open|Path\.of)\s*\("),
        "medium",
    ),
    SinkRule(
        "deserialization",
        "injection",
        rx(r"\b(deserialize|pickle\.loads|yaml\.load|ObjectInputStream|readObject|BinaryFormatter|unserialize)\s*\("),
        "high",
    ),
    SinkRule(
        "html_output",
        "xss",
        rx(
            r"\b(innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|document\.write|render_template_string)\b|"
            r"\bres\.send\s*\(\s*(?:[`'\"][^`'\"]*<|.*\+.*)|"
            r"\breturn\s+(?:f?['\"][^'\"]*<|.*\+.*<)"
        ),
        "high",
    ),
    SinkRule(
        "external_request",
        "ssrf",
        rx(
            r"\b(?:requests|urllib\.request|axios|http|https)\.(?:get|post|put|patch|delete|request|urlopen|Get|Post)\s*\(|"
            r"(?<!def )\bfetch\s*\(|\b(?:RestTemplate|HttpClient)\.[A-Za-z_]\w*\s*\(|\.openConnection\s*\("
        ),
        "medium",
    ),
    SinkRule(
        "auth_primitive",
        "auth",
        rx(r"\b(jwt|token|password|bcrypt|compare|sign|verify|authenticate|login)\b|(?<!\.)\bsession\s*(?:\[|\.get\s*\(|\.pop\s*\()"),
        "low",
    ),
    SinkRule(
        "authorization_decision",
        "authz",
        rx(
            r"\b(?:if|elif|while|allow|deny|authorize|abort|raise|throw|forbidden|unauthorized)\b[^\n;]*\b"
            r"(?:isAdmin|hasPermission|authorize|can\(|policy|owner|tenant|role|permission|admin|bypass|user[_-]?id|account[_-]?id|userId|accountId)\b|"
            r"\b(?:isAdmin|hasPermission|authorize|can\()\s*\(|"
            r"\b(?:if|elif)\b[^\n;]*\brequest\.(?:args|query|values)\.get\s*\("
        ),
        "low",
    ),
)

SANITIZER_RULES: tuple[SanitizerRule, ...] = (
    SanitizerRule(
        "parameterized_query",
        rx(
            r"\b(prepare|PreparedStatement|parameterized|bind|bindParam)\b|\b(?:query|execute|exec|raw)\s*\([^,\n]+,\s*(?:\[|\(|\{|[A-Za-z_]\w*)|\$\d+"
        ),
        "high",
    ),
    SanitizerRule("html_encoding", rx(r"\b(escape|escapeHtml|htmlspecialchars|encodeForHTML|DOMPurify|sanitizeHtml)\b"), "high"),
    SanitizerRule("url_validation", rx(r"\b(allowlist|whitelist|isAllowedHost|isPrivate|isLoopback|net\.isIP|parse_url)\b"), "medium"),
    SanitizerRule(
        "type_validation",
        rx(
            r"\b(zod|joi|yup|validator|parseInt|Integer\.parseInt|Long\.parseLong|strconv\.Atoi|Number\(|int\(|UUID|isUUID|schema\.parse|validate)\b"
        ),
        "medium",
    ),
    SanitizerRule(
        "authorization_guard", rx(r"\b(requireAuth|requireUser|requireAdmin|authorize|hasPermission|can\(|owner|tenant|policy)\b"), "medium"
    ),
)


def sanitizer_matches_vuln_class(kind: str, vuln_class: VulnClass) -> bool:
    if vuln_class == "injection":
        return kind in {"parameterized_query", "type_validation"}
    if vuln_class == "xss":
        return kind == "html_encoding"
    if vuln_class == "ssrf":
        return kind in {"url_validation", "type_validation"}
    if vuln_class == "auth":
        return kind == "type_validation"
    if vuln_class == "authz":
        return kind == "authorization_guard"
    return False
