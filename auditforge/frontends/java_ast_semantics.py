"""AST-backed Java constant folding, container tracking, and security semantics.

Consumes the compiler-tree JSON emitted by ``AuditForgeJavaAstBridge.java`` to
prune statically unreachable ``if``/``switch``/ternary branches, model ``List``,
``Map``, and ``StringBuilder`` values, and detect multi-line Servlet/JCA/J2EE
sources, sinks, sanitizers, and cryptographic weaknesses without regex fragility.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field, replace
from typing import Any

from .language_frontend import LanguageFactBuilder, dedupe_strings
from .models import DataFlowFact, FunctionFact, SanitizerFact, SinkFact, SourceFact

_UNKNOWN = object()
_PRIMITIVE_OR_COMMON_TYPES = {
    "boolean",
    "byte",
    "char",
    "double",
    "float",
    "int",
    "long",
    "short",
    "string",
    "void",
    "object",
    "integer",
    "character",
    "bigdecimal",
    "biginteger",
}
_WEAK_HASH_ALGOS = {"md2", "md4", "md5", "sha", "sha1", "sha-1"}
_WEAK_CIPHER_ALGOS = {"DES", "DESEDE", "TRIPLE_DES", "RC2", "RC4", "ARCFOUR", "BLOWFISH", "IDEA"}
_CHECKSUM_RE = re.compile(r"checksum|etag|fingerprint|cache_?key|crc", re.I)
_SECURITY_STEMS_RE = re.compile(
    r"password|passwd|token|secret|signature|session|credential|cookie|remember|nonce|salt|csrf",
    re.I,
)
_SECURITY_WORDS = {
    "auth",
    "oauth",
    "authorize",
    "authorized",
    "authorization",
    "authenticate",
    "authentication",
    "otp",
    "pin",
    "sid",
    "key",
    "reset",
}
_WORD_SPLIT_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+")


def _has_security_context(text: str) -> bool:
    """Return True when an identifier or expression mentions security/auth material."""

    if not text:
        return False
    if _SECURITY_STEMS_RE.search(text):
        return True
    return any(part.lower() in _SECURITY_WORDS for part in _WORD_SPLIT_RE.findall(text))


_IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_NON_IDENT = {"true", "false", "null", "new", "return", "this", "super", "instanceof"}


class _JavaChar(str):
    """Distinct 1-character value so Java ``char`` participates in both equality and integer math."""

    def __new__(cls, ch: str) -> _JavaChar:
        return super().__new__(cls, ch)


@dataclass
class JavaAstSemanticsOverlay:
    """Additional semantic facts plus AST-pruned lines produced for a Java file."""

    dead_lines: set[int] = field(default_factory=set)
    overridden_flow_lines: set[int] = field(default_factory=set)
    replacement_flows: list[DataFlowFact] = field(default_factory=list)
    extra_flows: list[DataFlowFact] = field(default_factory=list)
    routes: list[Any] = field(default_factory=list)
    sources: list[SourceFact] = field(default_factory=list)
    sinks: list[SinkFact] = field(default_factory=list)
    sanitizers: list[SanitizerFact] = field(default_factory=list)
    suppressed_sinks: dict[int, set[str]] = field(default_factory=dict)


def _suppress_sink(overlay: JavaAstSemanticsOverlay, line: int, end_line: int, kind: str) -> None:
    for ln in range(max(1, line), max(line, end_line) + 1):
        overlay.suppressed_sinks.setdefault(ln, set()).add(kind)


# ---------------------------------------------------------------------------
# Bounded recursive-descent evaluator for Java constant expressions
# ---------------------------------------------------------------------------

_TOK_RE = re.compile(
    r"""
    (?P<WS>\s+)
    |(?P<STR>"(?:\\.|[^"\\])*")
    |(?P<CHAR>'(?:\\.|[^'\\])*')
    |(?P<HEX>0[xX][0-9a-fA-F_]+[lL]?)
    |(?P<FLOAT>\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?[fFdD]|\d[\d_]*\.\d[\d_]*)
    |(?P<INT>\d[\d_]*[lL]?)
    |(?P<OP>&&|\|\||<<|>>>|>>|==|!=|<=|>=|[+\-*/%&|^!~?:().,\[\]<>])
    |(?P<IDENT>[A-Za-z_$][A-Za-z0-9_$]*)
    """,
    re.VERBOSE,
)


def _decode_java_escapes(raw: str) -> str:
    return (
        raw.replace("\\\\", "\x00")
        .replace('\\"', '"')
        .replace("\\'", "'")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\x00", "\\")
    )


def _tokenize_java(expr: str) -> list[tuple[str, str]] | None:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        match = _TOK_RE.match(expr, pos)
        if match is None:
            return None
        pos = match.end()
        kind = match.lastgroup
        if kind and kind != "WS":
            tokens.append((kind, match.group()))
    return tokens


def _num_val(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, _JavaChar) and len(value) == 1:
        return ord(value)
    return None


def _is_const_value(value: Any) -> bool:
    return value is not _UNKNOWN


def _java_eq(left: Any, right: Any) -> Any:
    if left is _UNKNOWN or right is _UNKNOWN:
        return _UNKNOWN
    if left is None or right is None:
        return left is right
    if isinstance(left, _JavaChar) and isinstance(right, int) and not isinstance(right, bool):
        return ord(left) == right
    if isinstance(right, _JavaChar) and isinstance(left, int) and not isinstance(left, bool):
        return left == ord(right)
    if type(left) is bool or type(right) is bool:
        return type(left) is bool and type(right) is bool and left == right
    return left == right


class _JavaExprParser:
    def __init__(self, tokens: list[tuple[str, str]], env: dict[str, Any]) -> None:
        self.tokens = tokens
        self.env = env
        self.pos = 0
        self.depth = 0

    def peek(self, offset: int = 0) -> tuple[str, str] | None:
        idx = self.pos + offset
        return self.tokens[idx] if 0 <= idx < len(self.tokens) else None

    def match(self, *values: str) -> str | None:
        tok = self.peek()
        if tok and tok[1] in values:
            self.pos += 1
            return tok[1]
        return None

    def parse(self) -> Any:
        if not self.tokens or len(self.tokens) > 250:
            return _UNKNOWN
        value = self.parse_ternary()
        return value if self.pos == len(self.tokens) else _UNKNOWN

    def parse_ternary(self) -> Any:
        cond = self.parse_or()
        if self.match("?"):
            t_val = self.parse_ternary()
            if not self.match(":"):
                return _UNKNOWN
            f_val = self.parse_ternary()
            if cond is True:
                return t_val
            if cond is False:
                return f_val
            return _UNKNOWN
        return cond

    def parse_or(self) -> Any:
        left = self.parse_and()
        while self.match("||"):
            right = self.parse_and()
            if left is True or right is True:
                left = True
            elif left is False and right is False:
                left = False
            else:
                left = _UNKNOWN
        return left

    def parse_and(self) -> Any:
        left = self.parse_bitor()
        while self.match("&&"):
            right = self.parse_bitor()
            if left is False or right is False:
                left = False
            elif left is True and right is True:
                left = True
            else:
                left = _UNKNOWN
        return left

    def parse_bitor(self) -> Any:
        left = self.parse_bitxor()
        while self.match("|"):
            right = self.parse_bitxor()
            if isinstance(left, bool) and isinstance(right, bool):
                left = left | right
            elif isinstance(left, int) and isinstance(right, int) and not isinstance(left, bool) and not isinstance(right, bool):
                left = left | right
            else:
                left = _UNKNOWN
        return left

    def parse_bitxor(self) -> Any:
        left = self.parse_bitand()
        while self.match("^"):
            right = self.parse_bitand()
            if isinstance(left, bool) and isinstance(right, bool):
                left = left ^ right
            elif isinstance(left, int) and isinstance(right, int) and not isinstance(left, bool) and not isinstance(right, bool):
                left = left ^ right
            else:
                left = _UNKNOWN
        return left

    def parse_bitand(self) -> Any:
        left = self.parse_eq()
        while self.match("&"):
            right = self.parse_eq()
            if isinstance(left, bool) and isinstance(right, bool):
                left = left & right
            elif isinstance(left, int) and isinstance(right, int) and not isinstance(left, bool) and not isinstance(right, bool):
                left = left & right
            else:
                left = _UNKNOWN
        return left

    def parse_eq(self) -> Any:
        left = self.parse_rel()
        while (op := self.match("==", "!=")) is not None:
            right = self.parse_rel()
            eq = _java_eq(left, right)
            left = eq if op == "==" else (not eq if eq is not _UNKNOWN else _UNKNOWN)
        return left

    def parse_rel(self) -> Any:
        left = self.parse_shift()
        while (op := self.match("<", "<=", ">", ">=")) is not None:
            right = self.parse_shift()
            ln, rn = _num_val(left), _num_val(right)
            if ln is None or rn is None:
                left = _UNKNOWN
            elif op == "<":
                left = ln < rn
            elif op == "<=":
                left = ln <= rn
            elif op == ">":
                left = ln > rn
            else:
                left = ln >= rn
        return left

    def parse_shift(self) -> Any:
        left = self.parse_add()
        while (op := self.match("<<", ">>", ">>>")) is not None:
            right = self.parse_add()
            if isinstance(left, int) and isinstance(right, int) and not isinstance(left, bool) and not isinstance(right, bool):
                shift = right & 0x1F
                if op == "<<":
                    left = left << shift
                elif op == ">>":
                    left = left >> shift
                else:
                    left = (left & 0xFFFFFFFF) >> shift
            else:
                left = _UNKNOWN
        return left

    def parse_add(self) -> Any:
        left = self.parse_mul()
        while (op := self.match("+", "-")) is not None:
            right = self.parse_mul()
            if op == "+":
                if isinstance(left, str) and not isinstance(left, _JavaChar):
                    left = f"{left}{right}" if right is not _UNKNOWN and right is not None else _UNKNOWN
                elif isinstance(right, str) and not isinstance(right, _JavaChar):
                    left = f"{left}{right}" if left is not _UNKNOWN and left is not None else _UNKNOWN
                else:
                    ln, rn = _num_val(left), _num_val(right)
                    left = (ln + rn) if (ln is not None and rn is not None) else _UNKNOWN
            else:
                ln, rn = _num_val(left), _num_val(right)
                left = (ln - rn) if (ln is not None and rn is not None) else _UNKNOWN
        return left

    def parse_mul(self) -> Any:
        left = self.parse_unary()
        while (op := self.match("*", "/", "%")) is not None:
            right = self.parse_unary()
            ln, rn = _num_val(left), _num_val(right)
            if ln is None or rn is None:
                left = _UNKNOWN
            elif op == "*":
                left = ln * rn
            elif rn == 0:
                left = _UNKNOWN
            elif op == "/":
                if isinstance(ln, int) and isinstance(rn, int):
                    left = int(ln / rn)  # Java truncates integer division toward zero.
                else:
                    left = ln / rn
            else:
                if isinstance(ln, int) and isinstance(rn, int):
                    left = int(math.fmod(ln, rn))
                else:
                    left = ln % rn
        return left

    def parse_unary(self) -> Any:
        self.depth += 1
        if self.depth > 48:
            return _UNKNOWN
        try:
            if self.match("+"):
                v = _num_val(self.parse_unary())
                return v if v is not None else _UNKNOWN
            if self.match("-"):
                v = _num_val(self.parse_unary())
                return -v if v is not None else _UNKNOWN
            if self.match("!"):
                v = self.parse_unary()
                return (not v) if isinstance(v, bool) else _UNKNOWN
            if self.match("~"):
                v = self.parse_unary()
                return ~v if isinstance(v, int) and not isinstance(v, bool) else _UNKNOWN
            # Handle primitive casts like (int) expr or (char) 65.
            if self.peek() == ("OP", "(") and self.peek(1) and self.peek(2) == ("OP", ")"):
                cast_name = self.peek(1)[1]  # type: ignore[index]
                if cast_name in {"int", "long", "short", "byte", "char", "float", "double", "String"}:
                    self.pos += 3
                    inner = self.parse_unary()
                    if inner is _UNKNOWN:
                        return _UNKNOWN
                    if cast_name == "char" and isinstance(inner, int) and 0 <= inner <= 0x10FFFF:
                        return _JavaChar(chr(inner))
                    if cast_name in {"int", "long", "short", "byte"}:
                        nv = _num_val(inner)
                        return int(nv) if nv is not None else _UNKNOWN
                    if cast_name in {"float", "double"}:
                        nv = _num_val(inner)
                        return float(nv) if nv is not None else _UNKNOWN
                    if cast_name == "String" and isinstance(inner, str):
                        return str(inner)
                    return _UNKNOWN
            return self.parse_postfix()
        finally:
            self.depth -= 1

    def parse_postfix(self) -> Any:
        val = self.parse_primary()
        while True:
            if self.match("."):
                tok = self.peek()
                if tok is None or tok[0] != "IDENT":
                    return _UNKNOWN
                member = tok[1]
                self.pos += 1
                if self.match("("):
                    args = self._parse_arg_list()
                    if args is None:
                        return _UNKNOWN
                    val = self._eval_member_call(val, member, args)
                else:
                    if isinstance(val, tuple) and val[0] == "STATIC":
                        val = (val[1], f"{val[1]}.{member}") if "." not in val[1] else ("STATIC", f"{val[1]}.{member}")
                    else:
                        return _UNKNOWN
            elif self.match("["):
                idx = self.parse_ternary()
                if not self.match("]"):
                    return _UNKNOWN
                if isinstance(val, (list, tuple)) and not isinstance(val, str) and isinstance(idx, int) and 0 <= idx < len(val):
                    val = val[idx]
                else:
                    return _UNKNOWN
            else:
                break
        return val

    def _parse_arg_list(self) -> list[Any] | None:
        args: list[Any] = []
        if self.match(")"):
            return args
        while True:
            args.append(self.parse_ternary())
            if self.match(","):
                continue
            if self.match(")"):
                return args
            return None

    def _eval_member_call(self, target: Any, method: str, args: list[Any]) -> Any:
        if isinstance(target, tuple) and target[0] == "CLASS":
            cls_name = target[1]
            if cls_name == "String" and method == "valueOf" and len(args) == 1 and args[0] is not _UNKNOWN:
                return str(args[0])
            if cls_name == "Integer" and method in {"parseInt", "valueOf"} and len(args) == 1 and isinstance(args[0], str):
                try:
                    return int(str(args[0]).strip())
                except ValueError:
                    return _UNKNOWN
            if cls_name == "Math" and args and all(_num_val(a) is not None for a in args):
                nums = [_num_val(a) for a in args]
                if method == "abs" and len(nums) == 1 and nums[0] is not None:
                    return abs(nums[0])
                if method == "max" and len(nums) == 2 and nums[0] is not None and nums[1] is not None:
                    return max(nums[0], nums[1])
                if method == "min" and len(nums) == 2 and nums[0] is not None and nums[1] is not None:
                    return min(nums[0], nums[1])
            return _UNKNOWN
        if target is _UNKNOWN or any(a is _UNKNOWN for a in args):
            return _UNKNOWN
        if isinstance(target, str):
            raw_s = str(target)
            if method == "length" and not args:
                return len(raw_s)
            if method == "isEmpty" and not args:
                return len(raw_s) == 0
            if method == "charAt" and len(args) == 1 and isinstance(args[0], int) and not isinstance(args[0], bool):
                idx = args[0]
                return _JavaChar(raw_s[idx]) if 0 <= idx < len(raw_s) else _UNKNOWN
            if method == "substring":
                if len(args) == 1 and isinstance(args[0], int) and 0 <= args[0] <= len(raw_s):
                    return raw_s[args[0] :]
                if len(args) == 2 and isinstance(args[0], int) and isinstance(args[1], int) and 0 <= args[0] <= args[1] <= len(raw_s):
                    return raw_s[args[0] : args[1]]
            if method == "toUpperCase" and not args:
                return raw_s.upper()
            if method == "toLowerCase" and not args:
                return raw_s.lower()
            if method == "trim" and not args:
                return raw_s.strip()
            if method == "equals" and len(args) == 1:
                return isinstance(args[0], str) and raw_s == str(args[0])
            if method == "equalsIgnoreCase" and len(args) == 1 and isinstance(args[0], str):
                return raw_s.lower() == str(args[0]).lower()
            if method == "contains" and len(args) == 1 and isinstance(args[0], str):
                return str(args[0]) in raw_s
            if method == "startsWith" and len(args) == 1 and isinstance(args[0], str):
                return raw_s.startswith(str(args[0]))
            if method == "endsWith" and len(args) == 1 and isinstance(args[0], str):
                return raw_s.endswith(str(args[0]))
            if method == "replace" and len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], str):
                return raw_s.replace(str(args[0]), str(args[1]))
            if method == "concat" and len(args) == 1 and isinstance(args[0], str):
                return raw_s + str(args[0])
        return _UNKNOWN

    def parse_primary(self) -> Any:
        if self.match("("):
            inner = self.parse_ternary()
            return inner if self.match(")") else _UNKNOWN
        tok = self.peek()
        if tok is None:
            return _UNKNOWN
        kind, text = tok
        self.pos += 1
        if kind == "STR":
            return _decode_java_escapes(text[1:-1])
        if kind == "CHAR":
            decoded = _decode_java_escapes(text[1:-1])
            return _JavaChar(decoded[0]) if len(decoded) == 1 else _UNKNOWN
        if kind == "INT":
            try:
                return int(text.rstrip("lL").replace("_", ""), 10)
            except ValueError:
                return _UNKNOWN
        if kind == "HEX":
            try:
                return int(text.rstrip("lL").replace("_", ""), 16)
            except ValueError:
                return _UNKNOWN
        if kind == "FLOAT":
            try:
                return float(text.rstrip("fFdD").replace("_", ""))
            except ValueError:
                return _UNKNOWN
        if kind == "IDENT":
            if text == "true":
                return True
            if text == "false":
                return False
            if text == "null":
                return None
            if text in self.env:
                return self.env[text]
            if text in {"String", "Integer", "Math"}:
                return ("CLASS", text)
            if self.match("."):
                # Try chained variable/field lookup in env or ignore call gracefully.
                parts = [text]
                while True:
                    nxt = self.peek()
                    if nxt and nxt[0] == "IDENT":
                        self.pos += 1
                        parts.append(nxt[1])
                        if self.match("("):
                            args = self._parse_arg_list()
                            if args is None:
                                return _UNKNOWN
                            receiver_val = self.env.get(parts[0], _UNKNOWN)
                            if len(parts) == 2:
                                return self._eval_member_call(receiver_val, parts[1], args)
                            return _UNKNOWN
                        if not self.match("."):
                            break
                    else:
                        return _UNKNOWN
                joined = ".".join(parts)
                return self.env.get(joined, _UNKNOWN)
            if self.match("("):
                self._parse_arg_list()
                return _UNKNOWN
            return _UNKNOWN
        return _UNKNOWN


def eval_java_constant(expr: str, env: dict[str, Any] | None = None) -> Any:
    """Evaluate a side-effect-free Java expression to a Python value, or ``_UNKNOWN``."""
    stripped = (expr or "").strip()
    if not stripped:
        return _UNKNOWN
    tokens = _tokenize_java(stripped)
    if not tokens:
        return _UNKNOWN
    return _JavaExprParser(tokens, env or {}).parse()


def _split_ternary(expr: str) -> tuple[str, str, str] | None:
    """Split a top-level Java ``cond ? a : b`` expression outside strings and parens."""
    depth = 0
    quote: str | None = None
    escaped = False
    q_idx = -1
    ternary_depth = 0
    for idx, ch in enumerate(expr):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
        elif ch in {"(", "["}:
            depth += 1
        elif ch in {")", "]"}:
            depth = max(0, depth - 1)
        elif depth == 0:
            if ch == "?":
                if q_idx < 0:
                    q_idx = idx
                ternary_depth += 1
            elif ch == ":":
                if ternary_depth == 1 and q_idx >= 0:
                    return expr[:q_idx].strip(), expr[q_idx + 1 : idx].strip(), expr[idx + 1 :].strip()
                ternary_depth = max(0, ternary_depth - 1)
    return None


def _expr_variables(expr: str) -> list[str]:
    clean = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", expr or "")
    return dedupe_strings([m.group(0) for m in _IDENT_RE.finditer(clean) if m.group(0) not in _NON_IDENT])


def _in_ranges(ln: int, ranges: list[tuple[int, int]]) -> bool:
    return any(s <= ln <= e for s, e in ranges if s > 0 and e >= s)


def _nonconst_arg_vars(
    arg_texts: list[str],
    arg_sources: list[list[str]],
    snap: dict[str, Any],
    idx: int,
) -> list[str]:
    if idx >= len(arg_texts):
        return []
    if _is_const_value(eval_java_constant(arg_texts[idx], snap)):
        return []
    return arg_sources[idx] if idx < len(arg_sources) else _expr_variables(arg_texts[idx])


def _simple_java_type(type_name: str) -> str:
    base = re.sub(r"<.*>", "", (type_name or "").strip())
    base = base.removesuffix("[]").strip()
    return base.rsplit(".", 1)[-1]


def _normalize_algo(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _is_weak_cipher_transform(transform: str) -> bool:
    parts = [part.strip().upper() for part in transform.split("/") if part.strip()]
    if not parts:
        return False
    algo = parts[0]
    mode = parts[1] if len(parts) > 1 else ""
    if algo in _WEAK_CIPHER_ALGOS or "PBEWITHMD5" in algo or "PBEWITHSHA1" in algo:
        return True
    if algo not in {"RSA", "RSA_OAEP"} and (mode == "ECB" or (not mode and algo in {"AES", "AESWRAP"})):
        return True
    return False


def _add_semantic_sink(
    builder: LanguageFactBuilder,
    kind: str,
    expression: str,
    line: int,
    variables: list[str],
    *,
    function: FunctionFact | None,
    confidence: str = "high",
    out_sinks: list[SinkFact],
    end_line: int | None = None,
) -> None:
    sink = builder.add_sink(kind, expression, line, variables, confidence=confidence, function=function, end_line=end_line)
    out_sinks.append(replace(sink, analysis_method="ast"))
    builder.result.sinks.pop()


def _add_semantic_source(
    builder: LanguageFactBuilder,
    kind: str,
    expression: str,
    line: int,
    variables: list[str],
    *,
    function: FunctionFact | None,
    out_sources: list[SourceFact],
    end_line: int | None = None,
) -> None:
    source = builder.add_source(kind, expression, line, variables, function=function, end_line=end_line)
    out_sources.append(replace(source, analysis_method="ast"))
    builder.result.sources.pop()


def _add_semantic_sanitizer(
    builder: LanguageFactBuilder,
    kind: str,
    expression: str,
    line: int,
    out_vars: list[str],
    in_vars: list[str],
    *,
    applies_to: list[str],
    function: FunctionFact | None,
    out_sanitizers: list[SanitizerFact],
    end_line: int | None = None,
    symbol: str | None = None,
) -> None:
    san = builder.add_sanitizer(
        kind, expression, line, out_vars, in_vars, function=function, applies_to=applies_to, end_line=end_line, symbol=symbol
    )
    out_sanitizers.append(replace(san, analysis_method="ast"))
    builder.result.sanitizers.pop()


def _extract_dead_lines_and_const_flows(
    builder: LanguageFactBuilder,
    raw: dict[str, Any],
    function_map: dict[str, FunctionFact],
) -> tuple[set[int], set[int], list[DataFlowFact], list[DataFlowFact], dict[str, dict[int, dict[str, Any]]]]:
    """Run per-method constant propagation, dead-branch pruning, and container tracking."""
    dead_lines: set[int] = set()
    overridden_lines: set[int] = set()
    replacement_flows: list[DataFlowFact] = []
    extra_flows: list[DataFlowFact] = []
    const_snapshots: dict[str, dict[int, dict[str, Any]]] = {}

    assignments_by_scope: dict[str, list[dict[str, Any]]] = {}
    controls_by_scope: dict[str, list[dict[str, Any]]] = {}
    calls_by_scope: dict[str, list[dict[str, Any]]] = {}
    variables_by_scope: dict[str, list[dict[str, Any]]] = {}
    for item in raw.get("assignments") or []:
        if isinstance(item, dict):
            assignments_by_scope.setdefault(str(item.get("scopeKey") or ""), []).append(item)
    for item in raw.get("controls") or []:
        if isinstance(item, dict):
            controls_by_scope.setdefault(str(item.get("scopeKey") or ""), []).append(item)
    for item in raw.get("calls") or []:
        if isinstance(item, dict):
            calls_by_scope.setdefault(str(item.get("scopeKey") or ""), []).append(item)
    for item in raw.get("variables") or []:
        if isinstance(item, dict):
            variables_by_scope.setdefault(str(item.get("scopeKey") or ""), []).append(item)

    all_scopes = set(assignments_by_scope) | set(controls_by_scope) | set(calls_by_scope) | set(variables_by_scope)
    for scope_key in all_scopes:
        fn = function_map.get(scope_key)
        env: dict[str, Any] = {}
        list_slots: dict[str, list[tuple[Any, list[str]]]] = {}
        snapshots: dict[int, dict[str, Any]] = {}
        const_snapshots[scope_key] = snapshots

        var_decl_types: dict[tuple[int, str], str] = {
            (int(v.get("line") or 0), str(v.get("name") or "").strip()): _simple_java_type(str(v.get("type") or ""))
            for v in variables_by_scope.get(scope_key, [])
        }
        calls_by_line: dict[int, list[dict[str, Any]]] = {}
        for k in calls_by_scope.get(scope_key, []):
            calls_by_line.setdefault(int(k.get("line") or 0), []).append(k)

        # Track unpruned control regions so assignments inside runtime branches are not marked safe-constant.
        unpruned_ranges: list[tuple[int, int]] = []
        pruned_ranges: list[tuple[int, int]] = []

        events: list[tuple[int, int, str, dict[str, Any]]] = []
        for c in controls_by_scope.get(scope_key, []):
            events.append((int(c.get("line") or 0), 0, "control", c))
        for a in assignments_by_scope.get(scope_key, []):
            events.append((int(a.get("line") or 0), 1, "assign", a))
        for k in calls_by_scope.get(scope_key, []):
            events.append((int(k.get("line") or 0), 2, "call", k))
        events.sort(key=lambda e: (e[0], e[1]))

        for line, _prio, kind, item in events:
            if line <= 0:
                continue
            snapshots[line] = dict(env)
            if line in dead_lines or _in_ranges(line, pruned_ranges):
                continue
            snapshots[line] = dict(env)
            if kind == "control":
                ckind = str(item.get("kind") or "")
                cond = str(item.get("condition") or "")
                end_line = int(item.get("endLine") or line)
                if ckind == "if" and "thenStartLine" in item:
                    t_start = int(item.get("thenStartLine") or 0)
                    t_end = int(item.get("thenEndLine") or 0)
                    e_start = int(item.get("elseStartLine") or 0)
                    e_end = int(item.get("elseEndLine") or 0)
                    val = eval_java_constant(cond, env) if not _in_ranges(line, unpruned_ranges) else _UNKNOWN
                    if val is True:
                        if e_start > 0 and e_end >= e_start:
                            pruned_ranges.append((e_start, e_end))
                            dead_lines.update(range(e_start, e_end + 1))
                    elif val is False:
                        if t_start > 0 and t_end >= t_start:
                            pruned_ranges.append((t_start, t_end))
                            dead_lines.update(range(t_start, t_end + 1))
                    else:
                        unpruned_ranges.append((line, end_line))
                elif ckind == "switch" and "cases" in item:
                    val = eval_java_constant(cond, env) if not _in_ranges(line, unpruned_ranges) else _UNKNOWN
                    cases = item.get("cases") or []
                    if _is_const_value(val) and cases:
                        matched_indices: set[int] = set()
                        found_idx = -1
                        default_idx = -1
                        for idx, c in enumerate(cases):
                            if c.get("isDefault"):
                                default_idx = idx
                                continue
                            for lbl in c.get("labels") or []:
                                lbl_val = eval_java_constant(str(lbl), env)
                                if _is_const_value(lbl_val) and _java_eq(val, lbl_val) is True:
                                    found_idx = idx
                                    break
                            if found_idx >= 0:
                                break
                        start_idx = found_idx if found_idx >= 0 else default_idx
                        if start_idx >= 0:
                            for idx in range(start_idx, len(cases)):
                                matched_indices.add(idx)
                                if cases[idx].get("hasBreak"):
                                    break
                        for idx, c in enumerate(cases):
                            if idx not in matched_indices:
                                cs = int(c.get("startLine") or 0)
                                ce = int(c.get("endLine") or 0)
                                if cs > 0 and ce >= cs:
                                    pruned_ranges.append((cs, ce))
                                    dead_lines.update(range(cs, ce + 1))
                    else:
                        unpruned_ranges.append((line, end_line))
                elif ckind in {"for", "while", "catch"}:
                    unpruned_ranges.append((line, max(line, end_line)))
            elif kind == "assign":
                target = str(item.get("target") or "").strip()
                expr = str(item.get("expression") or "").strip()
                if not target:
                    continue
                unconditional = not _in_ranges(line, unpruned_ranges)
                # Handle ternary expressions specially so dead arms do not leak variables.
                ternary = _split_ternary(expr)
                if ternary is not None:
                    cond_e, then_e, else_e = ternary
                    cond_val = eval_java_constant(cond_e, env) if unconditional else _UNKNOWN
                    if cond_val is True or cond_val is False:
                        chosen_e = then_e if cond_val is True else else_e
                        chosen_const = eval_java_constant(chosen_e, env)
                        overridden_lines.add(line)
                        if _is_const_value(chosen_const) and "getparameter" not in chosen_e.lower():
                            env[target] = chosen_const
                            builder.add_assignment(target, [], expr, line, safe_overwrite=True, function=fn)
                            replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                        else:
                            env.pop(target, None)
                            builder.add_assignment(target, _expr_variables(chosen_e), expr, line, function=fn)
                            replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                        continue

                # Handle List.get(idx) assignment narrowing (with optional Java cast).
                _CAST_PREFIX_RE = r"(?:^\s*\(\s*[A-Za-z_$.][A-Za-z0-9_$.<>[\],\s]*\s*\)\s*)?"
                list_get = re.match(rf"{_CAST_PREFIX_RE}(?P<rec>[A-Za-z_$][\w$]*)\.get\s*\(\s*(?P<idx>[^)]+)\)$", expr)
                if list_get and list_get.group("rec") in list_slots:
                    rec = list_get.group("rec")
                    idx_val = eval_java_constant(list_get.group("idx"), env)
                    slots = list_slots[rec]
                    if isinstance(idx_val, int) and not isinstance(idx_val, bool) and 0 <= idx_val < len(slots):
                        slot_const, slot_srcs = slots[idx_val]
                        overridden_lines.add(line)
                        if _is_const_value(slot_const) and unconditional:
                            env[target] = slot_const
                            builder.add_assignment(target, [], expr, line, safe_overwrite=True, function=fn)
                        else:
                            env.pop(target, None)
                            builder.add_assignment(target, list(slot_srcs), expr, line, function=fn)
                        replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                        continue

                # Handle Map.get(key) assignment narrowing (with optional Java cast).
                map_get = re.match(rf"{_CAST_PREFIX_RE}(?P<rec>[A-Za-z_$][\w$]*)\.get\s*\(\s*(?P<key>[^)]+)\)$", expr)
                if map_get:
                    key_val = eval_java_constant(map_get.group("key"), env)
                    if isinstance(key_val, (str, int)) and not isinstance(key_val, bool):
                        rec = map_get.group("rec")
                        suffix = f"[{key_val!r}]" if isinstance(key_val, str) else f"[{key_val}]"
                        overridden_lines.add(line)
                        env.pop(target, None)
                        builder.add_assignment(target, [f"{rec}{suffix}"], expr, line, function=fn)
                        replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                        continue

                # Initialize ArrayList / LinkedList (including package-qualified forms & initial capacity).
                if (
                    re.search(r"\bnew\s+(?:java\.util\.)?(?:ArrayList|LinkedList|Vector|Stack)\s*(?:<[^;()]*>)?\s*\(", expr)
                    and unconditional
                ):
                    list_slots[target] = []
                    env.pop(target, None)
                    continue

                if re.search(r"\.new\s+", expr):
                    env.pop(target, None)
                    continue

                # Query executions return DB rows / XML nodes rather than copying the query string itself.
                assign_end = max(line, int(item.get("endLine") or line))
                line_calls: list[dict[str, Any]] = []
                for c_line in range(line, assign_end + 1):
                    line_calls.extend(calls_by_line.get(c_line, []))
                handled_query_result = False
                for k in line_calls:
                    rec = str(k.get("receiver") or "").strip()
                    method = str(k.get("methodName") or "").strip()
                    arg_sources = [list(x) for x in (k.get("argumentSources") or []) if isinstance(x, list)]
                    if (
                        (
                            method == "executeQuery"
                            or ((rec.endswith("JDBCtemplate") or "jdbctemplate" in rec.lower()) and method.startswith("query"))
                        )
                        and method in expr
                        and not re.search(r"\b(?:prepareStatement|prepareCall|createStatement)\b", expr)
                    ):
                        env.pop(target, None)
                        overridden_lines.add(line)
                        builder.add_assignment(target, [], expr, line, safe_overwrite=unconditional, function=fn, end_line=assign_end)
                        replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                        handled_query_result = True
                        break
                    if (
                        method in {"evaluate", "selectNodes", "selectSingleNode"}
                        and (
                            "xpath" in rec.lower()
                            or rec.lower() == "xp"
                            or "XPathConstants" in expr
                            or re.search(r"\b(?:xp|xpath)\w*\.", expr, re.I)
                        )
                        and method in expr
                    ):
                        # XPath.evaluate(expr, doc, ...) vs XPathExpression.evaluate(doc, ...)
                        doc_idx = 1 if (method == "evaluate" and len(arg_sources) >= 2) else 0
                        raw_doc_srcs = arg_sources[doc_idx] if doc_idx < len(arg_sources) else []
                        doc_srcs = [v for v in raw_doc_srcs if v not in {"XPathConstants", "javax", "xml", "xpath", "org"}]
                        env.pop(target, None)
                        overridden_lines.add(line)
                        builder.add_assignment(
                            target,
                            doc_srcs,
                            expr,
                            line,
                            safe_overwrite=(unconditional and not doc_srcs),
                            function=fn,
                            end_line=assign_end,
                        )
                        replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                        handled_query_result = True
                        break
                if handled_query_result:
                    continue

                # Primitive scalar declarations initialized purely via Random/Math (no variable args)
                # safely overwrite any same-named inner-block variable from earlier statements.
                decl_type = var_decl_types.get((line, target), "")
                if (
                    unconditional
                    and decl_type in {"int", "long", "double", "float", "boolean", "short", "byte", "char"}
                    and line_calls
                    and all(not [v for xs in (k.get("argumentSources") or []) for v in xs] for k in line_calls)
                    and re.search(r"\b(?:Random|ThreadLocalRandom|SecureRandom|Math)\b.*\.(?:next\w+|random)\s*\(", expr)
                ):
                    env.pop(target, None)
                    overridden_lines.add(line)
                    builder.add_assignment(target, [], expr, line, safe_overwrite=True, function=fn)
                    replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                    continue

                const_val = _UNKNOWN
                if (
                    unconditional
                    and "getparameter" not in expr.lower()
                    and "getheader" not in expr.lower()
                    and "getcookie" not in expr.lower()
                ):
                    const_val = eval_java_constant(expr, env)
                if _is_const_value(const_val) and unconditional:
                    env[target] = const_val
                    overridden_lines.add(line)
                    builder.add_assignment(target, [], expr, line, safe_overwrite=True, function=fn)
                    replacement_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                else:
                    env.pop(target, None)

            elif kind == "call":
                rec = str(item.get("receiver") or "").strip()
                method = str(item.get("methodName") or "").strip()
                arg_texts = [str(x) for x in (item.get("argumentTexts") or [])]
                arg_sources = [list(x) for x in (item.get("argumentSources") or []) if isinstance(x, list)]
                if (rec == "Collections" or rec.endswith(".Collections")) and method == "addAll" and len(arg_texts) >= 2:
                    col_target = arg_texts[0].strip()
                    if col_target and "." not in col_target:
                        add_srcs: list[str] = []
                        for idx in range(1, len(arg_texts)):
                            cval = eval_java_constant(arg_texts[idx], env)
                            if not _is_const_value(cval):
                                srcs_i = arg_sources[idx] if idx < len(arg_sources) else _expr_variables(arg_texts[idx])
                                add_srcs.extend(srcs_i)
                        add_srcs = dedupe_strings(add_srcs)
                        if add_srcs:
                            builder.add_assignment(
                                col_target, [col_target, *add_srcs], str(item.get("expression") or ""), line, function=fn
                            )
                            extra_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                    continue
                if not rec or "." in rec:
                    continue
                if method == "add" and arg_texts:
                    slots = list_slots.setdefault(rec, []) if not _in_ranges(line, unpruned_ranges) else list_slots.get(rec)
                    added_srcs: list[str] = []
                    if len(arg_texts) == 1:
                        cval = eval_java_constant(arg_texts[0], env)
                        added_srcs = [] if _is_const_value(cval) else (arg_sources[0] if arg_sources else _expr_variables(arg_texts[0]))
                        if slots is not None:
                            slots.append((cval, added_srcs))
                    elif len(arg_texts) == 2:
                        idx_val = eval_java_constant(arg_texts[0], env)
                        cval = eval_java_constant(arg_texts[1], env)
                        added_srcs = (
                            [] if _is_const_value(cval) else (arg_sources[1] if len(arg_sources) > 1 else _expr_variables(arg_texts[1]))
                        )
                        if slots is not None:
                            if isinstance(idx_val, int) and 0 <= idx_val <= len(slots):
                                slots.insert(idx_val, (cval, added_srcs))
                            else:
                                list_slots.pop(rec, None)
                    if added_srcs:
                        builder.add_assignment(rec, [rec, *added_srcs], str(item.get("expression") or ""), line, function=fn)
                        extra_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                elif method == "remove" and len(arg_texts) == 1 and rec in list_slots:
                    idx_val = eval_java_constant(arg_texts[0], env)
                    if isinstance(idx_val, int) and 0 <= idx_val < len(list_slots[rec]):
                        list_slots[rec].pop(idx_val)
                        if all(not slot_srcs for _, slot_srcs in list_slots[rec]) and not _in_ranges(line, unpruned_ranges):
                            builder.add_assignment(rec, [], str(item.get("expression") or ""), line, safe_overwrite=True, function=fn)
                            extra_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                    else:
                        list_slots.pop(rec, None)
                elif method == "clear" and rec in list_slots:
                    list_slots[rec].clear()
                    if not _in_ranges(line, unpruned_ranges):
                        builder.add_assignment(rec, [], str(item.get("expression") or ""), line, safe_overwrite=True, function=fn)
                        extra_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                elif method == "put" and len(arg_texts) >= 2:
                    key_val = eval_java_constant(arg_texts[0], env)
                    val_expr = arg_texts[1]
                    val_const = eval_java_constant(val_expr, env)
                    val_srcs = [] if _is_const_value(val_const) else (arg_sources[1] if len(arg_sources) > 1 else _expr_variables(val_expr))
                    if isinstance(key_val, (str, int)) and not isinstance(key_val, bool):
                        suffix = f"[{key_val!r}]" if isinstance(key_val, str) else f"[{key_val}]"
                        builder.add_assignment(
                            f"{rec}{suffix}",
                            val_srcs,
                            str(item.get("expression") or ""),
                            line,
                            safe_overwrite=_is_const_value(val_const) and not _in_ranges(line, unpruned_ranges),
                            function=fn,
                        )
                        extra_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
                elif method == "append" and arg_texts:
                    app_srcs = arg_sources[0] if arg_sources else _expr_variables(arg_texts[0])
                    if app_srcs:
                        builder.add_assignment(rec, [rec, *app_srcs], str(item.get("expression") or ""), line, function=fn)
                        extra_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))

    return dead_lines, overridden_lines, replacement_flows, extra_flows, const_snapshots


def analyze_java_ast_semantics(
    source_file: Any,
    raw: dict[str, Any],
    builder: LanguageFactBuilder,
    function_map: dict[str, FunctionFact],
) -> JavaAstSemanticsOverlay:
    """Derive Java AST routes, dead branches, container flows, sources, sinks, and sanitizers."""
    overlay = JavaAstSemanticsOverlay()
    if "variables" not in raw and "imports" not in raw and "newClasses" not in raw:
        return overlay

    dead_lines, overridden_lines, replacement_flows, extra_flows, const_snapshots = _extract_dead_lines_and_const_flows(
        builder, raw, function_map
    )
    overlay.dead_lines = dead_lines
    overlay.overridden_flow_lines = overridden_lines
    overlay.replacement_flows = replacement_flows
    overlay.extra_flows = extra_flows

    imports_lower = " ".join(str(item.get("module") or "").lower() for item in (raw.get("imports") or []) if isinstance(item, dict))

    # Collect per-scope declared types, assignment-inferred types, and initializers.
    var_types_by_scope: dict[str, dict[str, str]] = {}
    assign_by_line_scope: dict[tuple[str, int], dict[str, Any]] = {}
    return_lines_by_scope: dict[str, set[int]] = {}
    for item in raw.get("variables") or []:
        if not isinstance(item, dict):
            continue
        scope_key = str(item.get("scopeKey") or "")
        name = str(item.get("name") or "").strip()
        vtype = _simple_java_type(str(item.get("type") or ""))
        init = str(item.get("initializer") or "")
        line = int(item.get("line") or 0)
        if not name:
            continue
        scope_types = var_types_by_scope.setdefault(scope_key, {})
        if vtype and vtype.lower() not in _PRIMITIVE_OR_COMMON_TYPES:
            scope_types[name] = vtype
        elif vtype == "Random" and "SecureRandom" in init:
            scope_types[name] = "SecureRandom"
        if "new SecureRandom" in init or "SecureRandom.getInstance" in init:
            scope_types[name] = "SecureRandom"
        elif "new Random" in init or "new java.util.Random" in init:
            scope_types[name] = "Random"
        elif ".getWriter(" in init or ".getOutputStream(" in init:
            scope_types[name] = "ResponseWriter"
        if init and line > 0:
            assign_by_line_scope[(scope_key, line)] = {"target": name, "expression": init, "line": line}

    for item in raw.get("assignments") or []:
        if isinstance(item, dict):
            scope_key = str(item.get("scopeKey") or "")
            line = int(item.get("line") or 0)
            expr = str(item.get("expression") or "")
            target = str(item.get("target") or "")
            if line > 0 and target:
                assign_by_line_scope[(scope_key, line)] = item
                scope_types = var_types_by_scope.setdefault(scope_key, {})
                if "new SecureRandom" in expr or "SecureRandom.getInstance" in expr:
                    scope_types[target] = "SecureRandom"
                elif "new Random" in expr or "new java.util.Random" in expr:
                    scope_types[target] = "Random"
                elif ".getWriter(" in expr or ".getOutputStream(" in expr:
                    scope_types[target] = "ResponseWriter"
                elif "new PrintWriter" in expr and not any(
                    marker in expr for marker in ("FileWriter", "FileOutputStream", "StringWriter", "ByteArrayOutputStream", "new File")
                ):
                    scope_types.setdefault(target, "PrintWriter")
                elif "Runtime.getRuntime(" in expr:
                    scope_types[target] = "Runtime"
                elif "new ProcessBuilder" in expr:
                    scope_types[target] = "ProcessBuilder"

    for item in raw.get("returns") or []:
        if isinstance(item, dict) and int(item.get("line") or 0) > 0:
            return_lines_by_scope.setdefault(str(item.get("scopeKey") or ""), set()).add(int(item["line"]))

    # Pre-check XXE hardening per scope.
    xxe_hardened_scopes: set[str] = set()
    for item in raw.get("calls") or []:
        if not isinstance(item, dict):
            continue
        line = int(item.get("line") or 0)
        if line in dead_lines:
            continue
        expr_l = str(item.get("expression") or "").lower()
        if "disallow-doctype-decl" in expr_l or "access_external_dtd" in expr_l or "external-general-entities" in expr_l:
            xxe_hardened_scopes.add(str(item.get("scopeKey") or ""))

    # Track cookie variables & setSecure flags per scope.
    cookie_secure_state: dict[tuple[str, str], bool] = {}
    cookies_added: set[tuple[str, int, str]] = set()

    # Emit AST routes (@WebServlet / HttpServlet, Spring mappings, JAX-RS)
    class_route_info: dict[str, tuple[str, bool, str]] = {}
    for cls in raw.get("classes") or []:
        if not isinstance(cls, dict):
            continue
        ckey = str(cls.get("key") or "")
        cname = str(cls.get("name") or "")
        cls_anns = [str(a) for a in (cls.get("annotations") or [])]
        ext = str(cls.get("extendsType") or "").rsplit(".", 1)[-1]
        prefix = ""
        servlet_path = ""
        is_servlet = ext == "HttpServlet"
        for ann in cls_anns:
            m_req = re.search(r"@(?:RequestMapping|Path)\s*\((.*)\)", ann, re.I | re.DOTALL)
            if m_req:
                m_str = re.search(r'["\']([^"\']+)["\']', m_req.group(1))
                if m_str:
                    prefix = m_str.group(1)
            m_ws = re.search(r"@WebServlet\s*\((.*)\)", ann, re.I | re.DOTALL)
            if m_ws:
                is_servlet = True
                m_named = re.search(r'(?:value|urlPatterns)\s*=\s*\{?\s*["\']([^"\']+)["\']', m_ws.group(1))
                m_str = m_named or re.search(r'["\']([^"\']+)["\']', m_ws.group(1))
                servlet_path = m_str.group(1) if m_str else f"/{cname}"
            elif "@webservlet" in ann.lower():
                is_servlet = True
        if ckey:
            class_route_info[ckey] = (prefix, is_servlet, servlet_path or f"/{cname}")

    # Emit routes from class/method annotations and Servlet handlers.
    for item in raw.get("functions") or []:
        if not isinstance(item, dict):
            continue
        skey = str(item.get("key") or "")
        fn = function_map.get(skey)
        ckey = str(item.get("classKey") or "")
        cls_prefix, cls_is_servlet, cls_servlet_path = class_route_info.get(ckey, ("", False, ""))
        anns = [str(a) for a in (item.get("annotations") or [])]
        name = str(item.get("name") or "")
        if fn is not None:
            emitted_explicit = False
            for ann in anns:
                m_map = re.search(r"@(Get|Post|Put|Patch|Delete)Mapping\s*(?:\((.*)\))?", ann, re.I | re.DOTALL)
                if m_map:
                    emitted_explicit = True
                    m_str = re.search(r'["\']([^"\']+)["\']', m_map.group(2) or "")
                    sub = m_str.group(1) if m_str else ""
                    path = f"/{cls_prefix.strip('/')}/{sub.strip('/')}".replace("//", "/") if cls_prefix or sub else "/"
                    route = builder.add_route(m_map.group(1).upper(), path, int(item.get("line") or 1), "spring", handler=fn)
                    overlay.routes.append(replace(route, analysis_method="ast"))
                    builder.result.routes.pop()
                else:
                    m_rm = re.search(r"@RequestMapping\s*(?:\((.*)\))?", ann, re.I | re.DOTALL)
                    if m_rm:
                        emitted_explicit = True
                        body = m_rm.group(1) or ""
                        rm_m = re.search(r"RequestMethod\.([A-Z]+)", body)
                        m_str = re.search(r'["\']([^"\']+)["\']', body)
                        sub = m_str.group(1) if m_str else ""
                        path = f"/{cls_prefix.strip('/')}/{sub.strip('/')}".replace("//", "/") if cls_prefix or sub else "/"
                        route = builder.add_route(rm_m.group(1) if rm_m else "ANY", path, int(item.get("line") or 1), "spring", handler=fn)
                        overlay.routes.append(replace(route, analysis_method="ast"))
                        builder.result.routes.pop()
            if (
                not emitted_explicit
                and cls_is_servlet
                and name in {"doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "service"}
            ):
                http_m = "ANY" if name == "service" else name[2:].upper()
                route = builder.add_route(http_m, cls_servlet_path, int(item.get("line") or 1), "servlet", handler=fn)
                overlay.routes.append(replace(route, analysis_method="ast"))
                builder.result.routes.pop()

    # First pass: track cookie.setSecure(...) state.
    for item in raw.get("calls") or []:
        if not isinstance(item, dict):
            continue
        line = int(item.get("line") or 0)
        if line <= 0 or line in dead_lines:
            continue
        scope_key = str(item.get("scopeKey") or "")
        rec = str(item.get("receiver") or "").strip()
        method = str(item.get("methodName") or "").strip()
        arg_texts = [str(x) for x in (item.get("argumentTexts") or [])]
        if method == "setSecure" and rec and arg_texts:
            snap = const_snapshots.get(scope_key, {}).get(line, {})
            flag = eval_java_constant(arg_texts[0], snap)
            if isinstance(flag, bool):
                cookie_secure_state[(scope_key, rec)] = flag

    # Collect non-security-direct PRNG calls for intra-method security-sink propagation.
    prng_events_by_scope: dict[str, list[tuple[int, str, str, list[str], FunctionFact | None]]] = {}
    emitted_weak_lines: set[int] = set()

    # Second pass: inspect calls for sources, sinks, sanitizers, weak_hash, weak_cipher, weak_random, cookies.
    for item in raw.get("calls") or []:
        if not isinstance(item, dict):
            continue
        line = int(item.get("line") or 0)
        end_line = max(line, int(item.get("endLine") or line))
        if line <= 0 or line in dead_lines:
            continue
        scope_key = str(item.get("scopeKey") or "")
        fn = function_map.get(scope_key)
        fn_name = fn.name if fn else ""
        rec = str(item.get("receiver") or "").strip()
        method = str(item.get("methodName") or "").strip()
        callee = str(item.get("callee") or "").strip()
        expr = str(item.get("expression") or "").strip()
        arg_texts = [str(x) for x in (item.get("argumentTexts") or [])]
        arg_sources = [list(x) for x in (item.get("argumentSources") or []) if isinstance(x, list)]
        scope_types = var_types_by_scope.get(scope_key, {})
        rec_type = scope_types.get(rec, "")
        snap = const_snapshots.get(scope_key, {}).get(line, {})
        assigned = assign_by_line_scope.get((scope_key, line))
        assign_target = str(assigned.get("target") or "") if assigned else ""
        target_vars = [assign_target] if assign_target else (["@return"] if line in return_lines_by_scope.get(scope_key, set()) else [])

        # --- Sources ---
        src_kind = ""
        if method in {"getParameter", "getParameterValues", "getParameterMap", "getParameterNames", "getQueryString"}:
            src_kind = "http_query"
        elif method in {"getPathInfo", "getRequestURI", "getRequestURL"}:
            src_kind = "http_path"
        elif method in {"getHeader", "getHeaders", "getHeaderNames"}:
            src_kind = "http_header"
        elif method in {"getCookies", "getCookie"}:
            src_kind = "cookie"
        elif method in {"getInputStream", "getReader"} and (
            "request" in rec.lower() or rec.lower() == "req" or scope_types.get(rec, "") in {"HttpServletRequest", "ServletRequest"}
        ):
            src_kind = "http_body"
        if src_kind and target_vars:
            _add_semantic_source(builder, src_kind, expr, line, target_vars, function=fn, out_sources=overlay.sources, end_line=end_line)

        # --- StringBuilder constructor/append handled in _extract_dead_lines, skip duplicate ---

        # --- Weak Hash (MessageDigest.getInstance / DigestUtils / Guava Hashing) ---
        is_checksum_ctx = bool(_CHECKSUM_RE.search(fn_name) or _CHECKSUM_RE.search(assign_target))
        if not is_checksum_ctx:
            if rec.endswith("MessageDigest") and method == "getInstance" and arg_texts:
                alg_val = eval_java_constant(arg_texts[0], snap)
                if isinstance(alg_val, str) and _normalize_algo(alg_val) in _WEAK_HASH_ALGOS:
                    _add_semantic_sink(builder, "weak_hash", expr, line, [], function=fn, out_sinks=overlay.sinks)
            elif (rec.endswith("DigestUtils") and re.match(r"^(?:md[245]|sha1?|md5Hex|sha1Hex|shaHex)$", method)) or (
                rec.endswith("Hashing") and method in {"md5", "sha1"}
            ):
                _add_semantic_sink(builder, "weak_hash", expr, line, [], function=fn, out_sinks=overlay.sinks)

        # --- Weak Hash / Safe Hash Suppression ---
        if rec.endswith("MessageDigest") and method == "getInstance" and arg_texts:
            alg_val = eval_java_constant(arg_texts[0], snap)
            if isinstance(alg_val, str) and _normalize_algo(alg_val) not in _WEAK_HASH_ALGOS:
                _suppress_sink(overlay, line, end_line, "weak_hash")

        # --- Weak Cipher (Cipher.getInstance) ---
        if rec.endswith("Cipher") and method == "getInstance" and arg_texts:
            tf_val = eval_java_constant(arg_texts[0], snap)
            if isinstance(tf_val, str) and _is_weak_cipher_transform(tf_val):
                _add_semantic_sink(builder, "weak_cipher", expr, line, [], function=fn, out_sinks=overlay.sinks)
            elif isinstance(tf_val, str):
                _suppress_sink(overlay, line, end_line, "weak_cipher")

        # --- Weak Random ---
        is_secure_prng = rec_type == "SecureRandom" or "securerandom" in rec.lower()
        is_prng_call = (
            method
            in {"nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean", "nextBytes", "nextGaussian", "ints", "longs", "doubles"}
            and not is_secure_prng
            and (rec_type == "Random" or "ThreadLocalRandom" in rec or "new Random(" in rec or "java.util.Random" in rec)
        ) or (rec in {"Math", "java.lang.Math"} and method == "random")
        if is_secure_prng:
            _suppress_sink(overlay, line, end_line, "weak_random")
        elif is_prng_call:
            mutated_vars = dedupe_strings(arg_sources[0]) if method == "nextBytes" and arg_sources else []
            mutated_text = arg_texts[0] if method == "nextBytes" and arg_texts else ""
            if (
                _has_security_context(assign_target)
                or _has_security_context(fn_name)
                or _has_security_context(expr)
                or _has_security_context(mutated_text)
            ):
                _add_semantic_sink(builder, "weak_random", expr, line, [], function=fn, out_sinks=overlay.sinks)
                emitted_weak_lines.add(line)
            else:
                prng_events_by_scope.setdefault(scope_key, []).append((line, expr, assign_target, mutated_vars, fn))

        # --- Insecure Cookie ---
        if method == "addCookie" and arg_texts:
            cookie_arg = arg_texts[0].strip()
            marker = (scope_key, line, cookie_arg)
            if marker not in cookies_added:
                cookies_added.add(marker)
                if (
                    cookie_arg.startswith("new Cookie")
                    or cookie_arg.startswith("new javax.servlet.http.Cookie")
                    or cookie_arg.startswith("new jakarta.servlet.http.Cookie")
                ):
                    _add_semantic_sink(builder, "insecure_cookie", expr, line, [], function=fn, out_sinks=overlay.sinks)
                elif not cookie_secure_state.get((scope_key, cookie_arg), False):
                    _add_semantic_sink(builder, "insecure_cookie", expr, line, [], function=fn, out_sinks=overlay.sinks)
                else:
                    _suppress_sink(overlay, line, end_line, "insecure_cookie")

        # --- Sanitizers ---
        all_arg_vars = dedupe_strings([v for vs in arg_sources for v in vs])
        san_out = [assign_target] if assign_target else []
        callee_l = callee.lower()
        if all_arg_vars:
            if any(
                tok in callee_l
                for tok in (
                    "encodeforhtml",
                    "encodeforjavascript",
                    "javascriptescape",
                    "htmlescape",
                    "escapehtml",
                    "forhtml",
                    "forxml",
                    "forjavascript",
                    "utils.encodeforhtml",
                )
            ):
                _add_semantic_sanitizer(
                    builder,
                    "html_escape",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=["html_output"],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )
            elif "encodeforsql" in callee_l:
                _add_semantic_sanitizer(
                    builder,
                    "sql_escape",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=["raw_sql"],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )
            elif "encodeforldap" in callee_l or "encodefordn" in callee_l:
                _add_semantic_sanitizer(
                    builder,
                    "ldap_escape",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=["ldap_injection"],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )
            elif "encodeforxpath" in callee_l:
                _add_semantic_sanitizer(
                    builder,
                    "xpath_escape",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=["xpath_injection"],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )
            elif "encodeforos" in callee_l:
                _add_semantic_sanitizer(
                    builder,
                    "command_escape",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=["command_execution"],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )
            elif "encodeforurl" in callee_l or "foruricomponent" in callee_l:
                _add_semantic_sanitizer(
                    builder,
                    "url_escape",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=["open_redirect", "external_request"],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )
            elif rec.endswith("FilenameUtils") and method in {"getName", "getBaseName"}:
                _add_semantic_sanitizer(
                    builder,
                    "path_basename",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=["file_path"],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )
            elif (
                rec in {"Integer", "Long", "Double", "Float", "Short"}
                and method in {"parseInt", "parseLong", "parseDouble", "parseFloat", "parseShort", "valueOf"}
            ) or (rec == "UUID" and method == "fromString"):
                _add_semantic_sanitizer(
                    builder,
                    "typed_conversion",
                    expr,
                    line,
                    san_out,
                    all_arg_vars,
                    applies_to=[
                        "raw_sql",
                        "command_execution",
                        "file_path",
                        "html_output",
                        "ldap_injection",
                        "xpath_injection",
                        "open_redirect",
                        "external_request",
                        "trust_boundary",
                    ],
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=end_line,
                )

        # --- Sinks ---
        # 1) SQL injection (suppress 0-arg PreparedStatement.executeQuery() and constant-SQL prepareStatement("SELECT ... ?"))
        if method in {"executeQuery", "executeUpdate", "execute"} and not arg_texts:
            _suppress_sink(overlay, line, end_line, "raw_sql")
        elif (
            method
            in {
                "executeQuery",
                "executeUpdate",
                "prepareStatement",
                "prepareCall",
                "addBatch",
                "createQuery",
                "createNativeQuery",
                "createCall",
            }
            and arg_texts
            or (method == "execute" and arg_texts and rec_type not in {"HttpClient", "CloseableHttpClient", "OkHttpClient"})
            or (rec_type in {"JdbcTemplate", "NamedParameterJdbcTemplate"} or "jdbctemplate" in rec.lower())
            and method
            in {
                "query",
                "queryForObject",
                "queryForList",
                "queryForMap",
                "queryForRowSet",
                "queryForStream",
                "update",
                "execute",
                "batchUpdate",
            }
            and arg_texts
        ):
            sql_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, 0)
            if sql_vars:
                _add_semantic_sink(builder, "raw_sql", expr, line, sql_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)
            else:
                _suppress_sink(overlay, line, end_line, "raw_sql")

        # 2) Command execution
        if (method == "exec" and ("Runtime" in rec or rec_type == "Runtime") and arg_texts) or (
            method == "command" and (rec_type == "ProcessBuilder" or "new ProcessBuilder" in rec or "pb" in rec.lower()) and arg_texts
        ):
            cmd_vars = dedupe_strings([v for i in range(len(arg_texts)) for v in _nonconst_arg_vars(arg_texts, arg_sources, snap, i)])
            if cmd_vars:
                _add_semantic_sink(
                    builder, "command_execution", expr, line, cmd_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line
                )
            else:
                _suppress_sink(overlay, line, end_line, "command_execution")

        # 3) Path traversal via static factories / Files
        if (rec in {"Paths", "Path"} and method in {"get", "of"} and arg_texts) or (
            rec == "Files"
            and method
            in {
                "readAllBytes",
                "readString",
                "write",
                "writeString",
                "newInputStream",
                "newOutputStream",
                "newBufferedReader",
                "newBufferedWriter",
                "delete",
                "deleteIfExists",
                "copy",
                "move",
            }
            and arg_texts
        ):
            fp_vars = dedupe_strings([v for i in range(len(arg_texts)) for v in _nonconst_arg_vars(arg_texts, arg_sources, snap, i)])
            if fp_vars:
                _add_semantic_sink(builder, "file_path", expr, line, fp_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)
            else:
                _suppress_sink(overlay, line, end_line, "file_path")

        # 4) LDAP injection
        if (
            method == "search"
            and len(arg_texts) >= 2
            and ("javax.naming" in imports_lower or rec_type in {"DirContext", "InitialDirContext", "LdapContext"})
        ):
            ldap_vars = dedupe_strings(
                [*_nonconst_arg_vars(arg_texts, arg_sources, snap, 0), *_nonconst_arg_vars(arg_texts, arg_sources, snap, 1)]
            )
            if ldap_vars:
                _add_semantic_sink(
                    builder, "ldap_injection", expr, line, ldap_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line
                )
            else:
                _suppress_sink(overlay, line, end_line, "ldap_injection")

        # 5) XPath injection
        if (
            method in {"evaluate", "compile"}
            and arg_texts
            and (rec_type == "XPath" or "xpath" in rec.lower() or "javax.xml.xpath" in imports_lower)
        ):
            xp_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, 0)
            if xp_vars:
                _add_semantic_sink(builder, "xpath_injection", expr, line, xp_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)
            else:
                _suppress_sink(overlay, line, end_line, "xpath_injection")

        # 6) XXE
        if (
            method in {"parse", "createXMLStreamReader", "newXMLStreamReader", "unmarshal"}
            and arg_texts
            and (
                rec_type in {"DocumentBuilder", "SAXParser", "XMLReader", "XMLInputFactory", "Unmarshaller"}
                or "builder" in rec.lower()
                or "sax" in rec.lower()
            )
        ):
            if scope_key in xxe_hardened_scopes:
                _suppress_sink(overlay, line, end_line, "xxe")
            else:
                xxe_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, 0)
                if xxe_vars:
                    _add_semantic_sink(builder, "xxe", expr, line, xxe_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)
                else:
                    _suppress_sink(overlay, line, end_line, "xxe")

        # 7) HTML output (only real response writers / template engines, NEVER System.out!)
        if rec.startswith(("System.out", "System.err")):
            _suppress_sink(overlay, line, end_line, "html_output")
        is_resp_writer_call = (
            method in {"write", "print", "println", "printf", "format", "append"}
            and (
                rec.endswith("getWriter()")
                or rec.endswith("getOutputStream()")
                or rec_type in {"ResponseWriter", "PrintWriter", "JspWriter", "ServletOutputStream"}
            )
            and not rec.startswith("System.")
        )
        if is_resp_writer_call and arg_texts:
            xss_vars = dedupe_strings([v for i in range(len(arg_texts)) for v in _nonconst_arg_vars(arg_texts, arg_sources, snap, i)])
            if xss_vars:
                _add_semantic_sink(
                    builder,
                    "html_output",
                    expr,
                    line,
                    xss_vars,
                    function=fn,
                    confidence="medium",
                    out_sinks=overlay.sinks,
                    end_line=end_line,
                )
            else:
                _suppress_sink(overlay, line, end_line, "html_output")

        # 8) Open redirect
        if (method == "sendRedirect" and arg_texts) or (
            method in {"setHeader", "addHeader"}
            and len(arg_texts) >= 2
            and str(eval_java_constant(arg_texts[0], snap)).lower() == "location"
        ):
            redir_idx = 1 if method in {"setHeader", "addHeader"} else 0
            redir_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, redir_idx)
            if redir_vars:
                _add_semantic_sink(
                    builder, "open_redirect", expr, line, redir_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line
                )
            else:
                _suppress_sink(overlay, line, end_line, "open_redirect")

        # 9) Trust boundary violation (HttpSession.setAttribute / putValue)
        if (
            method in {"setAttribute", "putValue"}
            and len(arg_texts) >= 2
            and (rec.endswith("getSession()") or "session" in rec.lower() or rec_type == "HttpSession")
        ):
            tb_vars = dedupe_strings(
                [*_nonconst_arg_vars(arg_texts, arg_sources, snap, 0), *_nonconst_arg_vars(arg_texts, arg_sources, snap, 1)]
            )
            if tb_vars:
                _add_semantic_sink(builder, "trust_boundary", expr, line, tb_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)
            else:
                _suppress_sink(overlay, line, end_line, "trust_boundary")

        # 10) SSRF & Deserialization
        if rec == "URI" and method == "create" and arg_texts:
            ssrf_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, 0)
            if ssrf_vars:
                _add_semantic_sink(
                    builder, "external_request", expr, line, ssrf_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line
                )
            else:
                _suppress_sink(overlay, line, end_line, "external_request")
        if method in {"readObject", "readUnshared"} and (
            rec_type == "ObjectInputStream" or "ois" in rec.lower() or "objectinput" in rec.lower()
        ):
            deser_vars = dedupe_strings(
                [rec, *[v for i in range(len(arg_texts)) for v in _nonconst_arg_vars(arg_texts, arg_sources, snap, i)]]
            )
            _add_semantic_sink(builder, "deserialization", expr, line, deser_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)

    # Third pass: inspect `newClasses` for File/ProcessBuilder/URL/StringBuilder/new Cookie/XMLDecoder.
    for item in raw.get("newClasses") or []:
        if not isinstance(item, dict):
            continue
        line = int(item.get("line") or 0)
        end_line = max(line, int(item.get("endLine") or line))
        if line <= 0 or line in dead_lines:
            continue
        scope_key = str(item.get("scopeKey") or "")
        fn = function_map.get(scope_key)
        ctype = _simple_java_type(str(item.get("type") or ""))
        expr = str(item.get("expression") or "").strip()
        arg_texts = [str(x) for x in (item.get("argumentTexts") or [])]
        arg_sources = [list(x) for x in (item.get("argumentSources") or []) if isinstance(x, list)]
        snap = const_snapshots.get(scope_key, {}).get(line, {})
        assigned = assign_by_line_scope.get((scope_key, line))
        assign_target = str(assigned.get("target") or "") if assigned else ""

        if ctype in {"File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "FileSystemResource"} and arg_texts:
            fp_vars = dedupe_strings(
                [v for i in range(min(2, len(arg_texts))) for v in _nonconst_arg_vars(arg_texts, arg_sources, snap, i)]
            )
            if fp_vars:
                _add_semantic_sink(builder, "file_path", expr, line, fp_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)
            else:
                _suppress_sink(overlay, line, end_line, "file_path")
        elif ctype == "ProcessBuilder" and arg_texts:
            cmd_vars = dedupe_strings([v for i in range(len(arg_texts)) for v in _nonconst_arg_vars(arg_texts, arg_sources, snap, i)])
            if cmd_vars:
                _add_semantic_sink(
                    builder, "command_execution", expr, line, cmd_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line
                )
            else:
                _suppress_sink(overlay, line, end_line, "command_execution")
        elif ctype == "URL" and arg_texts:
            url_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, 0)
            if url_vars:
                _add_semantic_sink(
                    builder, "external_request", expr, line, url_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line
                )
            else:
                _suppress_sink(overlay, line, end_line, "external_request")
        elif ctype in {"StringBuilder", "StringBuffer"} and assign_target and arg_texts:
            sb_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, 0)
            if sb_vars:
                builder.add_assignment(assign_target, sb_vars, expr, line, function=fn, end_line=end_line)
                overlay.extra_flows.append(replace(builder.result.data_flows.pop(), analysis_method="ast"))
        elif ctype == "XMLDecoder" and arg_texts:
            xd_vars = _nonconst_arg_vars(arg_texts, arg_sources, snap, 0)
            if xd_vars:
                _add_semantic_sink(builder, "deserialization", expr, line, xd_vars, function=fn, out_sinks=overlay.sinks, end_line=end_line)

    _emit_java_propagated_weak_random(
        builder,
        raw,
        function_map,
        var_types_by_scope,
        assign_by_line_scope,
        prng_events_by_scope,
        emitted_weak_lines,
        dead_lines,
        overlay,
    )
    _emit_java_guard_sanitizers(source_file, builder, raw, function_map, dead_lines, overlay)
    return overlay


def _emit_java_propagated_weak_random(
    builder: LanguageFactBuilder,
    raw: dict[str, Any],
    function_map: dict[str, FunctionFact],
    var_types_by_scope: dict[str, dict[str, str]],
    assign_by_line_scope: dict[tuple[str, int], dict[str, Any]],
    prng_events_by_scope: dict[str, list[tuple[int, str, str, list[str], FunctionFact | None]]],
    emitted_weak_lines: set[int],
    dead_lines: set[int],
    overlay: JavaAstSemanticsOverlay,
) -> None:
    """Emit weak_random when non-CSPRNG values flow into Java security sinks or security vars."""

    if not prng_events_by_scope:
        return

    def _emit_origin(line: int, expr: str, fn: FunctionFact | None) -> None:
        if line in emitted_weak_lines:
            return
        emitted_weak_lines.add(line)
        _add_semantic_sink(builder, "weak_random", expr, line, [], function=fn, out_sinks=overlay.sinks)

    assign_by_scope: dict[str, dict[int, tuple[str, str]]] = {}
    for (skey, line), item in assign_by_line_scope.items():
        if line <= 0 or line in dead_lines:
            continue
        target = str(item.get("target") or "").strip()
        expr = str(item.get("expression") or "").strip()
        if target:
            assign_by_scope.setdefault(skey, {})[line] = (target, expr)

    sec_sinks_by_scope: dict[str, dict[int, list[set[str]]]] = {}
    sb_appends_by_scope: dict[str, dict[int, list[tuple[str, set[str]]]]] = {}

    for item in raw.get("newClasses") or []:
        if not isinstance(item, dict):
            continue
        line = int(item.get("line") or 0)
        if line <= 0 or line in dead_lines:
            continue
        ctype = _simple_java_type(str(item.get("type") or ""))
        if ctype not in {"Cookie", "SecretKeySpec"}:
            continue
        skey = str(item.get("scopeKey") or "")
        arg_texts = [str(x) for x in (item.get("argumentTexts") or [])]
        arg_sources = [list(x) for x in (item.get("argumentSources") or []) if isinstance(x, list)]
        used = set(_expr_variables(" ".join(arg_texts)))
        for grp in arg_sources:
            used.update(grp)
        sec_sinks_by_scope.setdefault(skey, {}).setdefault(line, []).append(used)

    for item in raw.get("calls") or []:
        if not isinstance(item, dict):
            continue
        line = int(item.get("line") or 0)
        if line <= 0 or line in dead_lines:
            continue
        skey = str(item.get("scopeKey") or "")
        rec = str(item.get("receiver") or "").strip()
        method = str(item.get("methodName") or "").strip()
        rec_type = var_types_by_scope.get(skey, {}).get(rec, "")
        arg_texts = [str(x) for x in (item.get("argumentTexts") or [])]
        arg_sources = [list(x) for x in (item.get("argumentSources") or []) if isinstance(x, list)]
        used = set(_expr_variables(" ".join(arg_texts)))
        for grp in arg_sources:
            used.update(grp)

        if method == "append" and rec and (rec_type in {"StringBuilder", "StringBuffer"} or "sb" in rec.lower()):
            sb_appends_by_scope.setdefault(skey, {}).setdefault(line, []).append((rec, used))

        is_sec_call = (
            method == "addCookie"
            or (
                method in {"setAttribute", "putValue"}
                and (rec.endswith("getSession()") or "session" in rec.lower() or rec_type == "HttpSession")
            )
            or (
                method in {"setHeader", "addHeader"}
                and bool(arg_texts)
                and (_has_security_context(arg_texts[0]) or "set-cookie" in arg_texts[0].lower())
            )
            or (method == "setValue" and (rec_type == "Cookie" or "cookie" in rec.lower()))
            or (method == "update" and (rec.endswith("MessageDigest") or rec_type == "MessageDigest"))
            or (method == "init" and (rec.endswith("Cipher") or rec_type == "Cipher"))
        )
        if is_sec_call:
            sec_sinks_by_scope.setdefault(skey, {}).setdefault(line, []).append(used)

    for skey, prng_list in prng_events_by_scope.items():
        prng_by_line: dict[int, list[tuple[int, str, str, list[str], FunctionFact | None]]] = {}
        for ev in prng_list:
            prng_by_line.setdefault(ev[0], []).append(ev)
        scope_assigns = assign_by_scope.get(skey, {})
        scope_sinks = sec_sinks_by_scope.get(skey, {})
        scope_appends = sb_appends_by_scope.get(skey, {})
        all_lines = sorted(set(prng_by_line) | set(scope_assigns) | set(scope_sinks) | set(scope_appends))
        weak_origins: dict[str, tuple[int, str, FunctionFact | None]] = {}
        for ln in all_lines:
            if ln in prng_by_line:
                for p_line, p_expr, p_target, p_mutated, p_fn in prng_by_line[ln]:
                    origin = (p_line, p_expr, p_fn)
                    if ln in scope_sinks:
                        _emit_origin(p_line, p_expr, p_fn)
                    if p_target:
                        weak_origins[p_target] = origin
                    for mv in p_mutated:
                        weak_origins[mv] = origin
            elif ln in scope_assigns:
                target, expr = scope_assigns[ln]
                expr_vars = set(_expr_variables(expr))
                matched = next((weak_origins[v] for v in expr_vars if v in weak_origins), None)
                if matched is not None:
                    if _has_security_context(target):
                        _emit_origin(*matched)
                    weak_origins[target] = matched
                else:
                    weak_origins.pop(target, None)
            if ln in scope_appends:
                for sb_var, arg_vars in scope_appends[ln]:
                    matched = next((weak_origins[v] for v in arg_vars if v in weak_origins), None)
                    if matched is not None:
                        weak_origins[sb_var] = matched
            if ln in scope_sinks:
                for sink_vars in scope_sinks[ln]:
                    for sv in sink_vars:
                        if sv in weak_origins:
                            _emit_origin(*weak_origins[sv])


_ALL_JAVA_INJECTION_SINKS = [
    "raw_sql",
    "command_execution",
    "file_path",
    "html_output",
    "ldap_injection",
    "xpath_injection",
    "open_redirect",
    "external_request",
    "trust_boundary",
]
_GUARD_HELPER_IDENTIFIERS = {
    "Arrays",
    "Collections",
    "List",
    "Set",
    "Map",
    "Pattern",
    "StringUtils",
    "ESAPI",
    "String",
    "Character",
    "Objects",
}


def _strip_outer_parens(text: str) -> str:
    s = text.strip()
    while len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        quote: str | None = None
        escaped = False
        balanced = True
        for idx, ch in enumerate(s):
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                continue
            if ch in {'"', "'"}:
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx < len(s) - 1:
                    balanced = False
                    break
        if not balanced or depth != 0:
            break
        s = s[1:-1].strip()
    return s


def _emit_java_guard_sanitizers(
    source_file: Any,
    builder: LanguageFactBuilder,
    raw: dict[str, Any],
    function_map: dict[str, FunctionFact],
    dead_lines: set[int],
    overlay: JavaAstSemanticsOverlay,
) -> None:
    """Emit guarded-region sanitizers for Java allowlist, path prefix, equality, and regex guards."""

    for item in raw.get("controls") or []:
        if not isinstance(item, dict) or item.get("kind") != "if":
            continue
        line = int(item.get("line") or 0)
        if line <= 0 or line in dead_lines:
            continue
        t_start = int(item.get("thenStartLine") or 0)
        t_end = int(item.get("thenEndLine") or 0)
        if t_start <= 0 or t_end < t_start:
            continue
        scope_key = str(item.get("scopeKey") or "")
        fn = function_map.get(scope_key)
        fn_end = fn.anchor.end_line if fn else 0
        raw_cond = _strip_outer_parens(str(item.get("condition") or ""))
        if not raw_cond:
            continue
        negated = False
        cond = raw_cond
        if cond.startswith("!"):
            negated = True
            cond = _strip_outer_parens(cond[1:])

        guard_vars = [v for v in (item.get("variables") or []) if isinstance(v, str) and v and v not in _GUARD_HELPER_IDENTIFIERS]
        if not guard_vars:
            guard_vars = [v for v in _expr_variables(cond) if v not in _GUARD_HELPER_IDENTIFIERS]
        if not guard_vars:
            continue

        terminates = any(re.search(r"\b(?:return|throw)\b", ln) for ln in source_file.lines[max(0, t_start - 1) : t_end])
        region: tuple[int, int] | None = None
        if not negated:
            region = (t_start, t_end)
        elif terminates and fn_end > t_end:
            region = (t_end + 1, fn_end)

        applies_to: list[str] | None = None
        san_kind: str | None = None

        if region is not None:
            if ".startsWith(" in cond or ".isRelativeTo(" in cond:
                san_kind = "path_validation"
                applies_to = ["file_path"]
            elif (
                (
                    ".contains(" in cond
                    and (
                        any(tok in cond for tok in ("Arrays.asList", "List.of", "Set.of", "Collections"))
                        or re.search(r"\b(?:allow\w*|valid\w*|safe\w*|permit\w*)\s*\.\s*contains\s*\(", cond, re.I)
                    )
                )
                or "Pattern.matches(" in cond
                or ".matches(" in cond
                or "isValidInput(" in cond
                or "isNumeric(" in cond
            ):
                san_kind = "validation_guard"
                applies_to = list(_ALL_JAVA_INJECTION_SINKS)
            elif not negated:
                eq_left = re.fullmatch(r'"(?:\\.|[^"\\])+"\.(?:equals|equalsIgnoreCase)\(\s*([A-Za-z_$][\w$]*)\s*\)', cond)
                eq_right = re.fullmatch(r'([A-Za-z_$][\w$]*)\.(?:equals|equalsIgnoreCase)\(\s*"(?:\\.|[^"\\])+"\s*\)', cond)
                eq_match = eq_left or eq_right
                if eq_match:
                    san_kind = "constant_equality_guard"
                    applies_to = list(_ALL_JAVA_INJECTION_SINKS)
                    guard_vars = [eq_match.group(1)]

        if san_kind and applies_to and region is not None:
            g_start, g_end = region
            if g_end >= g_start:
                _add_semantic_sanitizer(
                    builder,
                    san_kind,
                    f"guarded-region: {raw_cond}",
                    g_start,
                    guard_vars,
                    guard_vars,
                    applies_to=applies_to,
                    function=fn,
                    out_sanitizers=overlay.sanitizers,
                    end_line=g_end,
                    symbol=f"guard:{san_kind}",
                )
