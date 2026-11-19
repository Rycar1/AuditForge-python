from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from ..core.models import (
    CallSiteFact,
    ClassFact,
    CodeAnchor,
    ControlFlowFact,
    DataFlowFact,
    FunctionFact,
    RouteFact,
    SanitizerFact,
    SinkFact,
    SourceFact,
)
from ..core.utils import sha256_text, stable_id


@dataclass
class PythonAnalysisResult:
    functions: list[FunctionFact] = field(default_factory=list)
    classes: list[ClassFact] = field(default_factory=list)
    routes: list[RouteFact] = field(default_factory=list)
    call_sites: list[CallSiteFact] = field(default_factory=list)
    data_flows: list[DataFlowFact] = field(default_factory=list)
    control_flows: list[ControlFlowFact] = field(default_factory=list)
    sources: list[SourceFact] = field(default_factory=list)
    sinks: list[SinkFact] = field(default_factory=list)
    sanitizers: list[SanitizerFact] = field(default_factory=list)


TAXONOMY_BY_SINK: dict[str, tuple[str, list[str]]] = {
    "raw_sql": ("sql_injection", ["CWE-89"]),
    "command_execution": ("command_injection", ["CWE-78"]),
    "file_path": ("path_traversal", ["CWE-22"]),
    "deserialization": ("unsafe_deserialization", ["CWE-502"]),
    "code_evaluation": ("code_injection", ["CWE-94", "CWE-95"]),
    "ldap_injection": ("ldap_injection", ["CWE-90"]),
    "xpath_injection": ("xpath_injection", ["CWE-643"]),
    "xxe": ("xxe", ["CWE-611"]),
    "html_output": ("cross_site_scripting", ["CWE-79"]),
    "external_request": ("server_side_request_forgery", ["CWE-918"]),
    "open_redirect": ("open_redirect", ["CWE-601"]),
    "auth_primitive": ("authentication_failure", ["CWE-287"]),
    "authorization_decision": ("authorization_failure", ["CWE-862"]),
    "trust_boundary": ("trust_boundary_violation", ["CWE-501"]),
    "insecure_cookie": ("insecure_cookie", ["CWE-614"]),
    "weak_hash": ("weak_cryptography", ["CWE-328", "CWE-327"]),
    "weak_cipher": ("weak_cryptography", ["CWE-327"]),
    "weak_random": ("insecure_randomness", ["CWE-330", "CWE-338"]),
}

_UNKNOWN = object()
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
    """Return True when an identifier or statement references security/auth material."""

    if not text:
        return False
    if _SECURITY_STEMS_RE.search(text):
        return True
    return any(part.lower() in _SECURITY_WORDS for part in _WORD_SPLIT_RE.findall(text))


_CHECKSUM_NAME_RE = re.compile(r"checksum|etag|fingerprint|cache_?key|crc", re.I)
_WEAK_HASH_ALGOS = {"md2", "md4", "md5", "sha", "sha1", "sha-1", "ripemd160"}
_WEAK_RANDOM_METHODS = {
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "sample",
    "uniform",
    "randbytes",
    "getrandbits",
    "gauss",
    "normalvariate",
    "triangular",
}
_SAFE_CSPRNG_PREFIXES = ("secrets.", "os.urandom", "uuid.uuid4", "ssl.rand_bytes")
_WEAK_CIPHER_CALLEES = {
    "crypto.cipher.des.new",
    "crypto.cipher.des3.new",
    "crypto.cipher.arc4.new",
    "crypto.cipher.arc2.new",
    "crypto.cipher.blowfish.new",
    "crypto.cipher.xor.new",
    "cryptodome.cipher.des.new",
    "cryptodome.cipher.des3.new",
    "cryptodome.cipher.arc4.new",
    "cryptodome.cipher.arc2.new",
    "cryptodome.cipher.blowfish.new",
    "cryptodome.cipher.xor.new",
    "cryptography.hazmat.primitives.ciphers.algorithms.tripledes",
    "cryptography.hazmat.primitives.ciphers.algorithms.blowfish",
    "cryptography.hazmat.primitives.ciphers.algorithms.arc4",
    "cryptography.hazmat.primitives.ciphers.modes.ecb",
}
_WEAK_SSL_PROTOCOLS = {
    "ssl.protocol_sslv2",
    "ssl.protocol_sslv3",
    "ssl.protocol_tlsv1",
    "ssl.protocol_tlsv1_1",
}
_XML_PARSER_CALLEES = {
    "xml.etree.elementtree.fromstring",
    "xml.etree.elementtree.parse",
    "xml.etree.elementtree.xml",
    "xml.etree.elementtree.iterparse",
    "xml.etree.celementtree.fromstring",
    "xml.etree.celementtree.parse",
    "xml.etree.celementtree.xml",
    "lxml.etree.fromstring",
    "lxml.etree.parse",
    "lxml.etree.xml",
    "lxml.etree.iterparse",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parsestring",
    "xml.dom.pulldom.parse",
    "xml.dom.pulldom.parsestring",
    "xml.sax.parse",
    "xml.sax.parsestring",
}


def _eval_python_constant(node: ast.AST | None, env: dict[str, Any]) -> Any:
    """Safely evaluate side-effect-free constant Python AST expressions."""

    if node is None:
        return _UNKNOWN
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id, _UNKNOWN)
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        path = _access_path(node)
        if path and path in env:
            return env[path]
        if isinstance(node, ast.Subscript):
            base = _eval_python_constant(node.value, env)
            if base is _UNKNOWN:
                return _UNKNOWN
            if isinstance(node.slice, ast.Slice):
                lower = None if node.slice.lower is None else _eval_python_constant(node.slice.lower, env)
                upper = None if node.slice.upper is None else _eval_python_constant(node.slice.upper, env)
                step = None if node.slice.step is None else _eval_python_constant(node.slice.step, env)
                if _UNKNOWN in (lower, upper, step):
                    return _UNKNOWN
                try:
                    return base[lower:upper:step]
                except Exception:  # noqa: BLE001
                    return _UNKNOWN
            idx = _eval_python_constant(node.slice, env)
            if idx is _UNKNOWN:
                return _UNKNOWN
            try:
                return base[idx]
            except Exception:  # noqa: BLE001
                return _UNKNOWN
        return _UNKNOWN
    if isinstance(node, ast.UnaryOp):
        operand = _eval_python_constant(node.operand, env)
        if operand is _UNKNOWN:
            return _UNKNOWN
        try:
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.Invert):
                return ~operand
        except Exception:  # noqa: BLE001
            return _UNKNOWN
        return _UNKNOWN
    if isinstance(node, ast.BinOp):
        left = _eval_python_constant(node.left, env)
        right = _eval_python_constant(node.right, env)
        if left is _UNKNOWN or right is _UNKNOWN:
            return _UNKNOWN
        if isinstance(node.op, ast.Pow) and isinstance(right, (int, float)) and abs(right) > 1000:
            return _UNKNOWN
        if isinstance(node.op, ast.Mult):
            if (isinstance(left, (str, bytes, tuple, list)) and isinstance(right, int) and len(left) * max(0, right) > 100_000) or (
                isinstance(right, (str, bytes, tuple, list)) and isinstance(left, int) and len(right) * max(0, left) > 100_000
            ):
                return _UNKNOWN
        try:
            ops = {
                ast.Add: lambda a, b: a + b,
                ast.Sub: lambda a, b: a - b,
                ast.Mult: lambda a, b: a * b,
                ast.Div: lambda a, b: a / b,
                ast.FloorDiv: lambda a, b: a // b,
                ast.Mod: lambda a, b: a % b,
                ast.Pow: lambda a, b: a**b,
                ast.LShift: lambda a, b: a << b,
                ast.RShift: lambda a, b: a >> b,
                ast.BitAnd: lambda a, b: a & b,
                ast.BitOr: lambda a, b: a | b,
                ast.BitXor: lambda a, b: a ^ b,
            }
            handler = ops.get(type(node.op))
            return handler(left, right) if handler else _UNKNOWN
        except Exception:  # noqa: BLE001
            return _UNKNOWN
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            val: Any = True
            for operand in node.values:
                val = _eval_python_constant(operand, env)
                if val is _UNKNOWN:
                    return _UNKNOWN
                if not val:
                    return val
            return val
        if isinstance(node.op, ast.Or):
            val = False
            for operand in node.values:
                val = _eval_python_constant(operand, env)
                if val is _UNKNOWN:
                    return _UNKNOWN
                if val:
                    return val
            return val
        return _UNKNOWN
    if isinstance(node, ast.Compare):
        left = _eval_python_constant(node.left, env)
        if left is _UNKNOWN:
            return _UNKNOWN
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            right = _eval_python_constant(comparator, env)
            if right is _UNKNOWN:
                return _UNKNOWN
            try:
                if isinstance(op, ast.Eq):
                    ok = left == right
                elif isinstance(op, ast.NotEq):
                    ok = left != right
                elif isinstance(op, ast.Lt):
                    ok = left < right
                elif isinstance(op, ast.LtE):
                    ok = left <= right
                elif isinstance(op, ast.Gt):
                    ok = left > right
                elif isinstance(op, ast.GtE):
                    ok = left >= right
                elif isinstance(op, ast.In):
                    ok = left in right
                elif isinstance(op, ast.NotIn):
                    ok = left not in right
                elif isinstance(op, ast.Is):
                    ok = left is right
                elif isinstance(op, ast.IsNot):
                    ok = left is not right
                else:
                    return _UNKNOWN
            except Exception:  # noqa: BLE001
                return _UNKNOWN
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.IfExp):
        test = _eval_python_constant(node.test, env)
        if test is _UNKNOWN:
            return _UNKNOWN
        return _eval_python_constant(node.body if test else node.orelse, env)
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for item in node.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                parts.append(item.value)
            elif isinstance(item, ast.FormattedValue):
                val = _eval_python_constant(item.value, env)
                if val is _UNKNOWN:
                    return _UNKNOWN
                spec = ""
                if item.format_spec is not None:
                    spec_val = _eval_python_constant(item.format_spec, env)
                    if spec_val is _UNKNOWN or not isinstance(spec_val, str):
                        return _UNKNOWN
                    spec = spec_val
                try:
                    parts.append(format(val, spec))
                except Exception:  # noqa: BLE001
                    return _UNKNOWN
            else:
                return _UNKNOWN
        return "".join(parts)
    if isinstance(node, (ast.Tuple, ast.List)):
        items = [_eval_python_constant(elt, env) for elt in node.elts]
        if any(item is _UNKNOWN for item in items):
            return _UNKNOWN
        return tuple(items) if isinstance(node, ast.Tuple) else items
    if isinstance(node, ast.Dict):
        out: dict[Any, Any] = {}
        for k_node, v_node in zip(node.keys, node.values, strict=False):
            if k_node is None:
                return _UNKNOWN
            k = _eval_python_constant(k_node, env)
            v = _eval_python_constant(v_node, env)
            if k is _UNKNOWN or v is _UNKNOWN or not isinstance(k, (str, int, float, bool, bytes, type(None))):
                return _UNKNOWN
            out[k] = v
        return out
    if isinstance(node, ast.Call):
        return _eval_python_const_call(node, env)
    return _UNKNOWN


def _eval_python_const_call(node: ast.Call, env: dict[str, Any]) -> Any:
    if node.keywords and not (isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "get"}):
        return _UNKNOWN
    args = [_eval_python_constant(arg, env) for arg in node.args]
    if isinstance(node.func, ast.Name):
        if any(arg is _UNKNOWN for arg in args):
            return _UNKNOWN
        fn_name = node.func.id
        builtins_map: dict[str, Any] = {
            "len": len,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "ord": ord,
            "chr": chr,
            "abs": abs,
            "min": min,
            "max": max,
            "round": round,
        }
        fn = builtins_map.get(fn_name)
        if fn is None:
            return _UNKNOWN
        try:
            return fn(*args)
        except Exception:  # noqa: BLE001
            return _UNKNOWN
    if isinstance(node.func, ast.Attribute):
        attr = node.func.attr
        if attr == "get" and len(args) in {1, 2} and args[0] is not _UNKNOWN:
            base_path = _access_path(node.func.value)
            if base_path and isinstance(args[0], (str, int, float)):
                suffix = f"[{args[0]!r}]" if isinstance(args[0], str) else f"[{args[0]}]"
                key_path = f"{base_path}{suffix}"
                if key_path in env:
                    return env[key_path]
        recv = _eval_python_constant(node.func.value, env)
        if recv is _UNKNOWN or any(arg is _UNKNOWN for arg in args):
            return _UNKNOWN
        if isinstance(recv, str) and attr in {
            "lower",
            "upper",
            "strip",
            "lstrip",
            "rstrip",
            "startswith",
            "endswith",
            "find",
            "index",
            "replace",
            "split",
            "join",
            "format",
            "title",
            "capitalize",
        }:
            try:
                kwargs = {kw.arg: _eval_python_constant(kw.value, env) for kw in node.keywords if kw.arg}
                if any(val is _UNKNOWN for val in kwargs.values()):
                    return _UNKNOWN
                return getattr(recv, attr)(*args, **kwargs)
            except Exception:  # noqa: BLE001
                return _UNKNOWN
        if isinstance(recv, dict) and attr == "get" and len(args) in {1, 2}:
            try:
                return recv.get(*args)
            except Exception:  # noqa: BLE001
                return _UNKNOWN
    return _UNKNOWN


def _assigned_target_roots(node: ast.AST) -> set[str]:
    roots: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = child.targets if isinstance(child, ast.Assign) else [child.target]
            for target in targets:
                for name in _target_names(target):
                    roots.add(name.split(".", 1)[0].split("[", 1)[0])
        elif isinstance(child, (ast.For, ast.AsyncFor)):
            for name in _target_names(child.target):
                roots.add(name.split(".", 1)[0].split("[", 1)[0])
    return roots


def analyze_python(source_file: Any) -> PythonAnalysisResult:
    """Parse one Python file and extract syntax-aware, scope-aware security facts.

    ``SyntaxError`` is deliberately allowed to escape. The repository scanner records
    it and falls back to explicitly labelled heuristic analysis for that file.
    """

    tree = ast.parse(source_file.content, filename=source_file.file.path, type_comments=True)
    parents = _parent_map(tree)
    import_aliases = _collect_import_aliases(tree, source_file.file.path)
    collector = _DefinitionCollector(source_file)
    collector.visit(tree)
    analyzer = _SemanticAnalyzer(source_file, parents, collector, import_aliases)
    analyzer.visit(tree)
    analyzer.add_route_parameter_sources()
    return analyzer.result


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _module_name(file_path: str) -> str:
    parts = file_path.replace("\\", "/").split("/")
    if not parts or not parts[-1].endswith(".py"):
        return ""
    parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(part for part in parts if part)


def _collect_import_aliases(tree: ast.AST, file_path: str) -> dict[str, str]:
    """Return import aliases resolved to repository-style dotted module names.

    The facts model intentionally stays language-neutral, so Python import resolution
    is encoded in the call-site callee name.  This is sufficient for the repository
    level call graph to distinguish ``a.load`` from ``b.load`` without persisting a
    second Python-only fact type.
    """

    aliases: dict[str, str] = {}
    module = _module_name(file_path)
    package_parts = module.split(".")[:-1] if module else []
    if file_path.replace("\\", "/").endswith("/__init__.py") or file_path == "__init__.py":
        package_parts = module.split(".") if module else []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".", 1)[0]
                aliases[local] = item.name if item.asname else local
        elif isinstance(node, ast.ImportFrom):
            base_parts = list(package_parts)
            if node.level:
                trim = max(0, node.level - 1)
                if trim:
                    base_parts = base_parts[:-trim] if trim <= len(base_parts) else []
            else:
                base_parts = []
            if node.module:
                base_parts.extend(node.module.split("."))
            base = ".".join(base_parts)
            for item in node.names:
                if item.name == "*":
                    continue
                local = item.asname or item.name
                aliases[local] = ".".join(part for part in (base, item.name) if part)
    return aliases


def _access_path(node: ast.AST | None) -> str | None:
    """Return a stable, compact access path for names, fields and subscriptions."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _access_path(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Subscript):
        base = _access_path(node.value)
        if not base:
            return None
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            suffix = f"[{key.value!r}]"
        elif isinstance(key, ast.Constant) and isinstance(key.value, (int, float)):
            suffix = f"[{key.value}]"
        else:
            suffix = "[*]"
        return f"{base}{suffix}"
    return None


def _loaded_names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    names: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Attribute(self, item: ast.Attribute) -> Any:
            if isinstance(item.ctx, ast.Load):
                path = _access_path(item)
                if path:
                    names.append(path)
                    return
            self.generic_visit(item)

        def visit_Subscript(self, item: ast.Subscript) -> Any:
            if isinstance(item.ctx, ast.Load):
                path = _access_path(item)
                if path:
                    names.append(path)
                    if not isinstance(item.slice, ast.Constant):
                        self.visit(item.slice)
                    return
            self.generic_visit(item)

        def visit_Name(self, item: ast.Name) -> Any:
            if isinstance(item.ctx, ast.Load):
                names.append(item.id)

    Visitor().visit(node)
    return list(dict.fromkeys(names))


def _target_names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        path = _access_path(node)
        return [path] if path else []
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _target_names(item)]
    return []


def _node_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)[:240]
    except (AttributeError, ValueError):
        return type(node).__name__


def _anchor(source_file: Any, node: ast.AST, symbol: str | None = None) -> CodeAnchor:
    start = max(1, int(getattr(node, "lineno", 1)))
    end = max(start, int(getattr(node, "end_lineno", start)))
    snippet = "\n".join(source_file.lines[start - 1 : end])
    return CodeAnchor(
        file=source_file.file.path,
        start_line=start,
        end_line=end,
        snippet_hash=sha256_text(snippet)[:16],
        symbol=symbol,
        start_col=getattr(node, "col_offset", None),
        end_col=getattr(node, "end_col_offset", None),
    )


def _range_anchor(source_file: Any, start: int, end: int, symbol: str) -> CodeAnchor:
    start = max(1, start)
    end = max(start, end)
    snippet = "\n".join(source_file.lines[start - 1 : end])
    return CodeAnchor(
        file=source_file.file.path,
        start_line=start,
        end_line=end,
        snippet_hash=sha256_text(snippet)[:16],
        symbol=symbol,
        start_col=0,
        end_col=None,
    )


def _function_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    out = [arg.arg for arg in args]
    if node.args.vararg:
        out.append(node.args.vararg.arg)
    if node.args.kwarg:
        out.append(node.args.kwarg.arg)
    return out


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, source_file: Any) -> None:
        self.source_file = source_file
        self.functions: list[FunctionFact] = []
        self.classes: list[ClassFact] = []
        self.function_nodes: dict[ast.AST, FunctionFact] = {}
        self.class_nodes: dict[ast.AST, ClassFact] = {}
        self._function_stack: list[FunctionFact] = []
        self._class_stack: list[ClassFact] = []
        self._qualifier_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        qualified = ".".join([*self._qualifier_stack, node.name])
        fact = ClassFact(
            id=stable_id("class", self.source_file.file.path, node.lineno, qualified),
            name=node.name,
            anchor=_anchor(self.source_file, node, qualified),
            qualified_name=qualified,
            analysis_method="ast",
        )
        self.classes.append(fact)
        self.class_nodes[node] = fact
        self._class_stack.append(fact)
        self._qualifier_stack.append(node.name)
        self.generic_visit(node)
        self._qualifier_stack.pop()
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join([*self._qualifier_stack, node.name])
        fact = FunctionFact(
            id=stable_id("function", self.source_file.file.path, node.lineno, qualified),
            name=node.name,
            anchor=_anchor(self.source_file, node, qualified),
            params=_function_params(node),
            qualified_name=qualified,
            parent_function_id=self._function_stack[-1].id if self._function_stack else None,
            class_id=self._class_stack[-1].id if self._class_stack else None,
            analysis_method="ast",
        )
        self.functions.append(fact)
        self.function_nodes[node] = fact
        self._function_stack.append(fact)
        self._qualifier_stack.append(node.name)
        self.generic_visit(node)
        self._qualifier_stack.pop()
        self._function_stack.pop()


class _SemanticAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        source_file: Any,
        parents: dict[ast.AST, ast.AST],
        definitions: _DefinitionCollector,
        import_aliases: dict[str, str],
    ) -> None:
        self.source_file = source_file
        self.parents = parents
        self.definitions = definitions
        self.import_aliases = import_aliases
        self.result = PythonAnalysisResult(
            functions=list(definitions.functions),
            classes=list(definitions.classes),
        )
        self._function_stack: list[FunctionFact] = []
        self._function_node_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self._class_stack: list[ClassFact] = []
        self._route_functions: list[tuple[FunctionFact, RouteFact]] = []
        self._const_env: dict[str, Any] = {}
        self._list_envs: dict[str, list[tuple[Any, list[str], tuple[int, str] | None]]] = {}
        self._branch_depth: int = 0
        self._html_vars: set[str] = set()
        self._formatted_str_vars: set[str] = set()
        self._weak_rand_vars: dict[str, tuple[int, str]] = {}
        self._var_types: dict[str, str] = {}
        self._has_ldap_import = any(
            value == "ldap" or value.startswith(("ldap.", "ldap3", "bonsai", "ldaptor")) for value in import_aliases.values()
        )
        self._has_xml_import = any(value.startswith(("xml.", "lxml.")) for value in import_aliases.values())
        self._has_defusedxml_import = any(value.startswith("defusedxml") for value in import_aliases.values())

    @property
    def scope_id(self) -> str | None:
        return self._function_stack[-1].id if self._function_stack else None

    @property
    def _in_route_scope(self) -> bool:
        if not self._function_stack:
            return False
        current_id = self._function_stack[-1].id
        return any(fn.id == current_id for fn, _ in self._route_functions)

    @property
    def _in_html_route_scope(self) -> bool:
        """True inside HTML-default routes (Flask), avoiding JSON-default APIs (FastAPI)."""

        if not self._function_stack:
            return False
        current_id = self._function_stack[-1].id
        has_flask = any(val == "flask" or val.startswith("flask.") for val in self.import_aliases.values())
        has_fastapi = any(val == "fastapi" or val.startswith("fastapi.") for val in self.import_aliases.values())
        for fn, route in self._route_functions:
            if fn.id != current_id:
                continue
            if route.framework == "flask-like" or (has_flask and not has_fastapi):
                return True
        return False

    def _resolved_name(self, node: ast.AST) -> str:
        raw = _qualified_name(node)
        if not raw:
            return ""
        root, separator, remainder = raw.partition(".")
        resolved = self.import_aliases.get(root)
        if not resolved:
            return raw
        return f"{resolved}.{remainder}" if separator else resolved

    def _call_result(self, node: ast.Call) -> str:
        callee = self._resolved_name(node.func) or _node_text(node.func)
        return f"@call:{callee}:{node.lineno}:{node.col_offset}"

    def _value_sources(self, node: ast.AST | None) -> list[str]:
        """Extract value dependencies while preserving function return identity.

        A call contributes a synthetic result path as well as its inputs.  The
        repository-level propagator removes the argument shortcut for calls it can
        resolve and therefore follows the callee's real return summary.  Keeping the
        arguments here provides a conservative fallback for unknown library calls.
        """

        if node is None:
            return []
        resolved_slot = self._resolve_list_subscript(node)
        if resolved_slot is not None:
            const_val, slot_sources, _weak_rand = resolved_slot
            if const_val is not _UNKNOWN:
                return []
            return list(slot_sources)
        names: list[str] = []

        class Visitor(ast.NodeVisitor):
            def __init__(self, analyzer: _SemanticAnalyzer) -> None:
                self.analyzer = analyzer

            def visit_Call(self, item: ast.Call) -> Any:
                names.append(self.analyzer._call_result(item))
                if isinstance(item.func, ast.Attribute):
                    attr = item.func.attr
                    if attr in {"execute", "executemany", "executescript"}:
                        rec_text = _node_text(item.func.value).lower()
                        is_db_call = (
                            isinstance(item.func.value, ast.Call)
                            and isinstance(item.func.value.func, ast.Attribute)
                            and item.func.value.func.attr in {"cursor", "connect"}
                        )
                        if (
                            rec_text in {"db", "conn", "connection", "cursor", "cur", "engine"}
                            or rec_text.endswith((".db", "_db", "conn", "connection", "cursor", "cur", "engine", ".session", "db_session"))
                            or is_db_call
                        ):
                            self.visit(item.func.value)
                            return
                    resolved_call = self.analyzer._resolved_name(item.func).lower()
                    if resolved_call == "elementpath.select" or _qualified_name(item.func).lower().endswith("elementpath.select"):
                        doc_node = item.args[0] if item.args else next((kw.value for kw in item.keywords if kw.arg == "root"), None)
                        if doc_node is not None:
                            self.visit(doc_node)
                        return
                    if attr in {"xpath", "find", "findall", "findtext", "iterfind"}:
                        rec_path = _access_path(item.func.value) or ""
                        if (
                            attr == "xpath"
                            or self.analyzer._var_types.get(rec_path) == "xml"
                            or self.analyzer._has_xml_import
                            or self.analyzer._has_defusedxml_import
                        ):
                            self.visit(item.func.value)
                            return
                    if resolved_call in {"lxml.etree.xpath", "lxml.etree.etxpath"}:
                        return
                    if attr == "get" and item.args:
                        base_path = _access_path(item.func.value)
                        if base_path and self.analyzer._var_types.get(base_path) == "configparser" and len(item.args) >= 2:
                            sec_val = _eval_python_constant(item.args[0], self.analyzer._const_env)
                            key_val = _eval_python_constant(item.args[1], self.analyzer._const_env)
                            if isinstance(sec_val, str) and isinstance(key_val, str):
                                cfg_key = f"{base_path}[{sec_val!r}][{key_val!r}]"
                                if cfg_key not in self.analyzer._const_env:
                                    names.append(cfg_key)
                                return
                        key_val = _eval_python_constant(item.args[0], self.analyzer._const_env)
                        if base_path and isinstance(key_val, (str, int, float)):
                            suffix = f"[{key_val!r}]" if isinstance(key_val, str) else f"[{key_val}]"
                            names.append(f"{base_path}{suffix}")
                            for argument in item.args[1:]:
                                self.visit(argument)
                            for keyword in item.keywords:
                                self.visit(keyword.value)
                            return
                    self.visit(item.func.value)
                for argument in item.args:
                    self.visit(argument)
                for keyword in item.keywords:
                    self.visit(keyword.value)

            def visit_Attribute(self, item: ast.Attribute) -> Any:
                if isinstance(item.ctx, ast.Load):
                    path = _access_path(item)
                    if path:
                        names.append(path)
                        return
                self.generic_visit(item)

            def visit_Subscript(self, item: ast.Subscript) -> Any:
                if isinstance(item.ctx, ast.Load):
                    resolved = self.analyzer._resolve_list_subscript(item)
                    if resolved is not None:
                        const_val, slot_sources, _weak_rand = resolved
                        if const_val is _UNKNOWN:
                            names.extend(slot_sources)
                        return
                    path = _access_path(item)
                    if path:
                        names.append(path)
                        if not isinstance(item.slice, ast.Constant):
                            self.visit(item.slice)
                        return
                self.generic_visit(item)

            def visit_Name(self, item: ast.Name) -> Any:
                if isinstance(item.ctx, ast.Load):
                    names.append(item.id)

        Visitor(self).visit(node)
        return list(dict.fromkeys(names))

    def _resolve_list_subscript(self, node: ast.AST) -> tuple[Any, list[str], tuple[int, str] | None] | None:
        if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Name):
            return None
        items = self._list_envs.get(node.value.id)
        if items is None:
            return None
        index_val = _eval_python_constant(node.slice, self._const_env)
        if not isinstance(index_val, int) or isinstance(index_val, bool):
            return None
        try:
            return items[index_val]
        except IndexError:
            return None

    def _invalidate_const_target(self, target: str) -> None:
        root = target.split(".", 1)[0].split("[", 1)[0]
        if target == root:
            self._const_env.pop(target, None)
            prefix_dot = f"{target}."
            prefix_bracket = f"{target}["
            for key in [k for k in self._const_env if k.startswith((prefix_dot, prefix_bracket))]:
                self._const_env.pop(key, None)
            self._list_envs.pop(target, None)
            self._weak_rand_vars.pop(target, None)
            self._html_vars.discard(target)
            self._formatted_str_vars.discard(target)
        else:
            self._const_env.pop(target, None)
            self._const_env.pop(root, None)
            self._list_envs.pop(root, None)
            self._weak_rand_vars.pop(target, None)

    def _snapshot_state(
        self,
    ) -> tuple[dict[str, Any], dict[str, list[Any]], set[str], set[str], dict[str, tuple[int, str]], dict[str, str]]:
        return (
            dict(self._const_env),
            {key: list(value) for key, value in self._list_envs.items()},
            set(self._html_vars),
            set(self._formatted_str_vars),
            dict(self._weak_rand_vars),
            dict(self._var_types),
        )

    def _restore_state(
        self,
        snapshot: tuple[dict[str, Any], dict[str, list[Any]], set[str], set[str], dict[str, tuple[int, str]], dict[str, str]],
    ) -> None:
        const_env, list_envs, html_vars, formatted_str_vars, weak_rand_vars, var_types = snapshot
        self._const_env = dict(const_env)
        self._list_envs = {key: list(value) for key, value in list_envs.items()}
        self._html_vars = set(html_vars)
        self._formatted_str_vars = set(formatted_str_vars)
        self._weak_rand_vars = dict(weak_rand_vars)
        self._var_types = dict(var_types)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._class_stack.append(self.definitions.class_nodes[node])
        for statement in node.body:
            self.visit(statement)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        fact = self.definitions.function_nodes[node]
        for route in self._routes_for_function(node, fact):
            self.result.routes.append(route)
            self._route_functions.append((fact, route))
        saved = self._snapshot_state()
        saved_depth = self._branch_depth
        assigned_roots = _assigned_target_roots(node)
        self._const_env = {
            key: value
            for key, value in saved[0].items()
            if isinstance(value, (int, float, str, bytes, bool, type(None))) and key.split(".", 1)[0].split("[", 1)[0] not in assigned_roots
        }
        self._list_envs = {}
        self._html_vars = set()
        self._formatted_str_vars = set()
        self._weak_rand_vars = {}
        self._var_types = {}
        self._branch_depth = 0
        self._function_stack.append(fact)
        self._function_node_stack.append(node)
        for statement in node.body:
            self.visit(statement)
        self._function_node_stack.pop()
        self._function_stack.pop()
        self._branch_depth = saved_depth
        self._restore_state(saved)

    def _routes_for_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        function: FunctionFact,
    ) -> list[RouteFact]:
        routes: list[RouteFact] = []
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            name = _qualified_name(decorator.func)
            method_name = name.rsplit(".", 1)[-1].lower()
            if method_name not in {"route", "get", "post", "put", "patch", "delete", "options", "head", "api_route"}:
                continue
            if not decorator.args or not isinstance(decorator.args[0], ast.Constant) or not isinstance(decorator.args[0].value, str):
                continue
            route_path = decorator.args[0].value
            methods: list[str] = []
            if method_name in {"route", "api_route"}:
                for keyword in decorator.keywords:
                    if keyword.arg != "methods" or not isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                        continue
                    methods = [
                        str(item.value).upper()
                        for item in keyword.value.elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    ]
            else:
                methods = [method_name.upper()]
            method = ",".join(methods) if methods else "GET"
            framework = "flask-like" if method_name == "route" else "fastapi-like"
            routes.append(
                RouteFact(
                    id=stable_id("route", self.source_file.file.path, decorator.lineno, f"{method}:{route_path}"),
                    method=method,
                    path=route_path,
                    framework=framework,
                    anchor=_anchor(self.source_file, decorator, f"{method} {route_path}"),
                    handler_function_id=function.id,
                    analysis_method="ast",
                )
            )
        return routes

    def add_route_parameter_sources(self) -> None:
        for function, route in self._route_functions:
            placeholders = set(re.findall(r"<(?:(?:[^>:]+):)?([^>]+)>|\{([^}:]+)(?::[^}]+)?}", route.path))
            names = {left or right for left, right in placeholders}
            function_node = next(
                (node for node, fact in self.definitions.function_nodes.items() if fact.id == function.id),
                None,
            )
            for param in function.params:
                kind = "http_path" if param in names else None
                if kind is None and route.framework == "fastapi-like" and function_node is not None:
                    kind = self._fastapi_parameter_source_kind(function_node, param)
                if kind is None:
                    continue
                anchor = CodeAnchor(
                    file=function.anchor.file,
                    start_line=function.anchor.start_line,
                    end_line=function.anchor.start_line,
                    snippet_hash=function.anchor.snippet_hash,
                    symbol=param,
                    start_col=function.anchor.start_col,
                    end_col=function.anchor.end_col,
                )
                self.result.sources.append(
                    SourceFact(
                        id=stable_id("source", anchor.file, anchor.start_line, f"{kind}:{function.id}:{param}"),
                        kind=kind,
                        expression=f"route parameter {param}",
                        anchor=anchor,
                        confidence="high",
                        variables=[param],
                        input_variables=[param],
                        enclosing_function_id=function.id,
                        analysis_method="ast",
                    )
                )

    def _fastapi_parameter_source_kind(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        param: str,
    ) -> str | None:
        positional = [*node.args.posonlyargs, *node.args.args]
        defaults: dict[str, ast.AST | None] = {argument.arg: None for argument in positional}
        offset = len(positional) - len(node.args.defaults)
        for index, default in enumerate(node.args.defaults):
            defaults[positional[offset + index].arg] = default
        defaults.update({argument.arg: default for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=False)})
        arguments = {argument.arg: argument for argument in [*positional, *node.args.kwonlyargs]}
        argument = arguments.get(param)
        if argument is None or param in {"self", "cls"}:
            return None
        default = defaults.get(param)
        annotation_text = _node_text(argument.annotation).lower() if argument.annotation is not None else ""
        default_name = ""
        if isinstance(default, ast.Call):
            default_name = _qualified_name(default.func).rsplit(".", 1)[-1].lower()
        combined = f"{annotation_text} {default_name}"
        if any(marker in combined for marker in ("depends", "security")):
            return None
        if default_name == "path":
            return "http_path"
        if default_name == "header":
            return "http_header"
        if default_name == "cookie":
            return "cookie"
        if default_name in {"body", "form"}:
            return "http_body"
        if default_name == "file" or "uploadfile" in annotation_text:
            return "file_upload"
        if default_name == "query":
            return "http_query"
        if any(marker in annotation_text for marker in ("request", "response", "backgroundtasks", "websocket")):
            return None
        primitive_markers = ("str", "int", "float", "bool", "bytes", "uuid", "date", "decimal", "literal")
        if not annotation_text or any(marker in annotation_text for marker in primitive_markers):
            return "http_query"
        return "http_body"

    def visit_Assign(self, node: ast.Assign) -> Any:
        self._handle_assignment(node, [t for t in node.targets], node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._handle_assignment(node, [node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._handle_assignment(node, [node.target], node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        for target_node in [node.target]:
            if self._is_session_subscript(target_node) and isinstance(target_node, ast.Subscript):
                tb_vars = list(dict.fromkeys([*self._value_sources(target_node.slice), *self._value_sources(node.value)]))
                self._add_sink(node, "trust_boundary", "auth", tb_vars, "high")
        for target in _target_names(node.target):
            sources = list(dict.fromkeys([target, *self._value_sources(node.value)]))
            self._add_assignment(node, target, sources, _node_text(node), safe_overwrite=False)
            self._invalidate_const_target(target)
            if self._expr_has_html(node.value) or any(name in self._html_vars for name in sources):
                self._html_vars.add(target)
            if self._in_html_route_scope and (
                self._is_formatted_str_expr(node.value)
                or target in self._formatted_str_vars
                or isinstance(self._const_env.get(target), str)
                or any(name in self._formatted_str_vars for name in sources)
            ):
                self._formatted_str_vars.add(target)
            if weak := self._expr_weak_rand(node.value):
                self._weak_rand_vars[target] = weak
        self.generic_visit(node)

    def _handle_assignment(self, node: ast.AST, target_nodes: list[ast.AST], value_node: ast.AST) -> None:
        for target_node in target_nodes:
            if self._is_session_subscript(target_node) and isinstance(target_node, ast.Subscript):
                tb_vars = list(dict.fromkeys([*self._value_sources(target_node.slice), *self._value_sources(value_node)]))
                self._add_sink(node, "trust_boundary", "auth", tb_vars, "high")

        targets = [name for target_node in target_nodes for name in _target_names(target_node)]
        expression = _node_text(value_node)
        has_source = self._contains_source_expr(value_node)
        if not has_source and len(targets) == 1 and targets[0].isidentifier() and isinstance(value_node, ast.Dict):
            target = targets[0]
            self._invalidate_const_target(target)
            has_dynamic = False
            for key_node, val_node in zip(value_node.keys, value_node.values, strict=False):
                if key_node is None:
                    has_dynamic = True
                    continue
                key_val = _eval_python_constant(key_node, self._const_env)
                if not isinstance(key_val, (str, int, float)) or isinstance(key_val, bool):
                    has_dynamic = True
                    continue
                suffix = f"[{key_val!r}]" if isinstance(key_val, str) else f"[{key_val}]"
                entry_target = f"{target}{suffix}"
                entry_const = _UNKNOWN if self._contains_source_expr(val_node) else _eval_python_constant(val_node, self._const_env)
                safe = entry_const is not _UNKNOWN and self._branch_depth == 0
                entry_sources = [] if entry_const is not _UNKNOWN else self._value_sources(val_node)
                self._add_assignment(node, entry_target, entry_sources, _node_text(val_node), safe_overwrite=safe)
                if entry_const is not _UNKNOWN and self._branch_depth == 0:
                    self._const_env[entry_target] = entry_const
                if weak := self._expr_weak_rand(val_node):
                    self._weak_rand_vars[entry_target] = weak
            if has_dynamic:
                self._add_assignment(node, f"{target}[*]", self._value_sources(value_node), expression, safe_overwrite=False)
            return

        if not has_source and len(targets) == 1 and targets[0].isidentifier() and isinstance(value_node, ast.List):
            if not any(isinstance(elt, ast.Starred) for elt in value_node.elts):
                target = targets[0]
                self._invalidate_const_target(target)
                self._list_envs[target] = [
                    (
                        _UNKNOWN if self._contains_source_expr(elt) else _eval_python_constant(elt, self._const_env),
                        self._value_sources(elt),
                        self._expr_weak_rand(elt),
                    )
                    for elt in value_node.elts
                ]
                self._add_assignment(node, target, self._value_sources(value_node), expression, safe_overwrite=False)
                return

        const_val = _UNKNOWN if has_source else self._eval_assignment_constant(value_node)
        sources = [] if const_val is not _UNKNOWN else self._value_sources(value_node)
        safe_overwrite = const_val is not _UNKNOWN and self._branch_depth == 0
        weak_rand = self._expr_weak_rand(value_node) if const_val is _UNKNOWN and not self._is_csprng_expr(value_node) else None
        inferred_type = self._infer_expr_type(value_node)
        has_html = self._expr_has_html(value_node) or any(name in self._html_vars for name in sources)
        has_formatted = self._in_html_route_scope and (
            self._is_formatted_str_expr(value_node) or any(name in self._formatted_str_vars for name in sources)
        )
        matched_weak = weak_rand or next((self._weak_rand_vars[name] for name in sources if name in self._weak_rand_vars), None)
        if matched_weak is not None and any(self._is_session_subscript(tn) for tn in target_nodes):
            self._add_weak_random_sink(value_node, matched_weak[1])

        for target in targets:
            self._add_assignment(node, target, sources, expression, safe_overwrite=safe_overwrite)
            if const_val is not _UNKNOWN and self._branch_depth == 0:
                self._invalidate_const_target(target)
                self._const_env[target] = const_val
            else:
                self._invalidate_const_target(target)
            if inferred_type and target.isidentifier():
                self._var_types[target] = inferred_type
            elif target.isidentifier():
                self._var_types.pop(target, None)
            if has_html and not (isinstance(const_val, str) and "<" not in const_val):
                self._html_vars.add(target)
            if has_formatted and const_val is _UNKNOWN:
                self._formatted_str_vars.add(target)
            if weak_rand is not None:
                self._weak_rand_vars[target] = weak_rand
                if _has_security_context(target):
                    self._add_weak_random_sink(value_node, weak_rand[1])

    def _eval_assignment_constant(self, node: ast.AST) -> Any:
        slot = self._resolve_list_subscript(node)
        if slot is not None:
            return slot[0]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and len(node.args) >= 2:
            base_path = _access_path(node.func.value)
            if base_path and self._var_types.get(base_path) == "configparser":
                sec_val = _eval_python_constant(node.args[0], self._const_env)
                key_val = _eval_python_constant(node.args[1], self._const_env)
                if isinstance(sec_val, str) and isinstance(key_val, str):
                    cfg_key = f"{base_path}[{sec_val!r}][{key_val!r}]"
                    if cfg_key in self._const_env:
                        return self._const_env[cfg_key]
        return _eval_python_constant(node, self._const_env)

    def _contains_source_expr(self, node: ast.AST) -> bool:
        for item in ast.walk(node):
            if isinstance(item, (ast.Call, ast.Attribute, ast.Subscript)) and self._source_kind(item):
                return True
        return False

    def _add_assignment(
        self,
        node: ast.AST,
        target: str,
        sources: list[str],
        expression: str,
        *,
        safe_overwrite: bool | None = None,
    ) -> None:
        if safe_overwrite is None:
            safe_overwrite = self._is_unconditional_literal_overwrite(node)
        self.result.data_flows.append(
            DataFlowFact(
                id=stable_id("dfg", self.source_file.file.path, node.lineno, f"assignment:{self.scope_id}:{target}:{expression}"),
                kind="assignment",
                target=target,
                sources=sources,
                expression=expression,
                anchor=_anchor(self.source_file, node, target),
                enclosing_function_id=self.scope_id,
                ssa_safe_overwrite=safe_overwrite,
                analysis_method="ast",
            )
        )

    def _is_unconditional_literal_overwrite(self, node: ast.AST) -> bool:
        value = getattr(node, "value", None)
        if not isinstance(value, ast.Constant):
            return False
        parent = self.parents.get(node)
        return isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module))

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None:
            expression = _node_text(node.value)
            sources = self._value_sources(node.value)
            self.result.data_flows.append(
                DataFlowFact(
                    id=stable_id("dfg", self.source_file.file.path, node.lineno, f"return:{self.scope_id}:{expression}"),
                    kind="return",
                    target=None,
                    sources=sources,
                    expression=expression,
                    anchor=_anchor(self.source_file, node, "return"),
                    enclosing_function_id=self.scope_id,
                    analysis_method="ast",
                )
            )
            html_target = self._return_html_expr(node.value)
            if html_target is not None:
                self._add_sink(html_target, "html_output", "xss", self._value_sources(html_target), "high")
            fn_name = self._function_stack[-1].name if self._function_stack else ""
            if _has_security_context(fn_name) and (weak := self._expr_weak_rand(node.value)):
                self._add_weak_random_sink(node.value, weak[1])
        self.generic_visit(node)

    def _return_html_expr(self, value: ast.AST) -> ast.AST | None:
        candidate = value.elts[0] if isinstance(value, ast.Tuple) and value.elts else value
        if self._is_html_expression(candidate):
            return candidate
        if isinstance(candidate, (ast.Name, ast.Subscript)):
            path = _access_path(candidate)
            if path and (path in self._html_vars or path.split("[", 1)[0] in self._html_vars):
                return candidate
        if self._in_html_route_scope and not self._is_non_html_return(candidate):
            if self._is_formatted_str_expr(candidate) and _loaded_names(candidate):
                return candidate
            if isinstance(candidate, (ast.Name, ast.Subscript)):
                path = _access_path(candidate)
                if path and (path in self._formatted_str_vars or path.split("[", 1)[0] in self._formatted_str_vars):
                    return candidate
        return None

    def visit_Call(self, node: ast.Call) -> Any:
        callee = self._resolved_name(node.func) or _node_text(node.func)
        argument_sources = [self._value_sources(arg) for arg in node.args]
        keyword_sources = {kw.arg or "**": self._value_sources(kw.value) for kw in node.keywords}
        self.result.call_sites.append(
            CallSiteFact(
                id=stable_id("callsite", self.source_file.file.path, node.lineno, f"{self.scope_id}:{callee}:{node.col_offset}"),
                callee=callee,
                anchor=_anchor(self.source_file, node, callee),
                enclosing_function_id=self.scope_id,
                argument_sources=argument_sources,
                keyword_sources=keyword_sources,
                analysis_method="ast",
            )
        )
        self.result.data_flows.append(
            DataFlowFact(
                id=stable_id("dfg", self.source_file.file.path, node.lineno, f"call:{self.scope_id}:{callee}:{node.col_offset}"),
                kind="call_argument",
                target=callee,
                sources=list(dict.fromkeys(name for names in [*argument_sources, *keyword_sources.values()] for name in names)),
                expression=_node_text(node),
                anchor=_anchor(self.source_file, node, callee),
                enclosing_function_id=self.scope_id,
                argument_sources=argument_sources,
                keyword_sources=keyword_sources,
                analysis_method="ast",
            )
        )
        source_kind = self._source_kind(node)
        if source_kind:
            self._add_source(node, source_kind)
        sink = self._sink_kind(node)
        if sink:
            kind, vuln_class, variables, confidence = sink
            self._add_sink(node, kind, vuln_class, variables, confidence)
        self._check_semantic_call_sinks(node, argument_sources, keyword_sources)
        sanitizer = self._sanitizer_kind(node)
        if sanitizer:
            kind, applies_to = sanitizer
            san_inputs = list(dict.fromkeys(name for names in argument_sources for name in names))
            self.result.sanitizers.append(
                SanitizerFact(
                    id=stable_id("sanitizer", self.source_file.file.path, node.lineno, f"{kind}:{node.col_offset}:{_node_text(node)}"),
                    kind=kind,
                    expression=_node_text(node),
                    anchor=_anchor(self.source_file, node, kind),
                    confidence="high" if kind in {"html_encoding", "parameterized_query"} else "medium",
                    variables=self._assigned_targets(node),
                    input_variables=san_inputs,
                    enclosing_function_id=self.scope_id,
                    analysis_method="ast",
                    applies_to_sink_kinds=applies_to,
                )
            )
        self._add_container_mutation(node, argument_sources, keyword_sources)
        self.generic_visit(node)

    def _add_container_mutation(
        self,
        node: ast.Call,
        argument_sources: list[list[str]],
        keyword_sources: dict[str, list[str]],
    ) -> None:
        if not isinstance(node.func, ast.Attribute):
            return
        container = _access_path(node.func.value)
        if not container:
            return
        method = node.func.attr.lower()
        flattened = list(dict.fromkeys(name for values in [*argument_sources, *keyword_sources.values()] for name in values))
        if self._is_session_expr(node.func.value) and method in {"update", "setdefault", "__setitem__"} and flattened:
            self._add_sink(node, "trust_boundary", "auth", flattened, "high")
        if method == "clear":
            self._invalidate_const_target(container)
            if container.isidentifier():
                self._list_envs[container] = []
            return
        if method == "pop" and container in self._list_envs:
            idx_val = 0 if not node.args else _eval_python_constant(node.args[0], self._const_env)
            if isinstance(idx_val, int) and not isinstance(idx_val, bool):
                try:
                    self._list_envs[container].pop(idx_val)
                except IndexError:
                    self._list_envs.pop(container, None)
            else:
                self._list_envs.pop(container, None)
            return
        if method in {"append", "extend", "add", "insert"} and (flattened or node.args):
            if method == "append" and len(node.args) == 1 and container in self._list_envs:
                arg = node.args[0]
                cval = _UNKNOWN if self._contains_source_expr(arg) else _eval_python_constant(arg, self._const_env)
                self._list_envs[container].append((cval, self._value_sources(arg), self._expr_weak_rand(arg)))
            elif method == "insert" and len(node.args) >= 2 and container in self._list_envs:
                idx_val = _eval_python_constant(node.args[0], self._const_env)
                if isinstance(idx_val, int) and not isinstance(idx_val, bool):
                    arg = node.args[1]
                    cval = _UNKNOWN if self._contains_source_expr(arg) else _eval_python_constant(arg, self._const_env)
                    self._list_envs[container].insert(idx_val, (cval, self._value_sources(arg), self._expr_weak_rand(arg)))
                else:
                    self._list_envs.pop(container, None)
            else:
                self._list_envs.pop(container, None)
            if flattened:
                self._add_assignment(node, f"{container}[*]", flattened, _node_text(node), safe_overwrite=False)
            for arg in node.args:
                if weak := self._expr_weak_rand(arg):
                    self._weak_rand_vars[f"{container}[*]"] = weak
            return
        if method == "write" and self._var_types.get(container) == "stringio" and flattened:
            self._add_assignment(node, container, [container, *flattened], _node_text(node), safe_overwrite=False)
            return
        if method == "set" and self._var_types.get(container) == "configparser" and len(node.args) >= 3:
            sec_val = _eval_python_constant(node.args[0], self._const_env)
            key_val = _eval_python_constant(node.args[1], self._const_env)
            if isinstance(sec_val, str) and isinstance(key_val, str):
                cfg_key = f"{container}[{sec_val!r}][{key_val!r}]"
                val_node = node.args[2]
                cval = _UNKNOWN if self._contains_source_expr(val_node) else _eval_python_constant(val_node, self._const_env)
                safe = cval is not _UNKNOWN and self._branch_depth == 0
                self._add_assignment(
                    node,
                    cfg_key,
                    [] if cval is not _UNKNOWN else self._value_sources(val_node),
                    _node_text(node),
                    safe_overwrite=safe,
                )
                if cval is not _UNKNOWN and self._branch_depth == 0:
                    self._const_env[cfg_key] = cval
                else:
                    self._const_env.pop(cfg_key, None)
                return
        if method not in {"update", "setdefault", "__setitem__"}:
            return
        added = False
        if node.args and isinstance(node.args[0], ast.Dict):
            for key, value in zip(node.args[0].keys, node.args[0].values, strict=False):
                key_val = _eval_python_constant(key, self._const_env)
                if isinstance(key_val, (str, int, float)) and not isinstance(key_val, bool):
                    suffix = f"[{key_val!r}]" if isinstance(key_val, str) else f"[{key_val}]"
                    cval = _UNKNOWN if self._contains_source_expr(value) else _eval_python_constant(value, self._const_env)
                    safe = cval is not _UNKNOWN and self._branch_depth == 0
                    self._add_assignment(
                        node,
                        f"{container}{suffix}",
                        [] if cval is not _UNKNOWN else self._value_sources(value),
                        _node_text(node),
                        safe_overwrite=safe,
                    )
                    if cval is not _UNKNOWN and self._branch_depth == 0:
                        self._const_env[f"{container}{suffix}"] = cval
                    else:
                        self._const_env.pop(f"{container}{suffix}", None)
                    if weak := self._expr_weak_rand(value):
                        self._weak_rand_vars[f"{container}{suffix}"] = weak
                    added = True
        elif method in {"setdefault", "__setitem__"} and len(node.args) >= 2:
            key_val = _eval_python_constant(node.args[0], self._const_env)
            if isinstance(key_val, (str, int, float)) and not isinstance(key_val, bool):
                suffix = f"[{key_val!r}]" if isinstance(key_val, str) else f"[{key_val}]"
                val_node = node.args[1]
                cval = _UNKNOWN if self._contains_source_expr(val_node) else _eval_python_constant(val_node, self._const_env)
                safe = cval is not _UNKNOWN and self._branch_depth == 0
                self._add_assignment(
                    node,
                    f"{container}{suffix}",
                    [] if cval is not _UNKNOWN else self._value_sources(val_node),
                    _node_text(node),
                    safe_overwrite=safe,
                )
                if cval is not _UNKNOWN and self._branch_depth == 0:
                    self._const_env[f"{container}{suffix}"] = cval
                else:
                    self._const_env.pop(f"{container}{suffix}", None)
                if weak := self._expr_weak_rand(val_node):
                    self._weak_rand_vars[f"{container}{suffix}"] = weak
                added = True
        for keyword in node.keywords:
            if keyword.arg:
                self._add_assignment(
                    node,
                    f"{container}[{keyword.arg!r}]",
                    self._value_sources(keyword.value),
                    _node_text(node),
                    safe_overwrite=False,
                )
                added = True
        if not added and flattened:
            self._add_assignment(node, f"{container}[*]", flattened, _node_text(node), safe_overwrite=False)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        if isinstance(node.ctx, ast.Load) and not isinstance(self.parents.get(node), ast.Call):
            source_kind = self._source_kind(node)
            if source_kind:
                self._add_source(node, source_kind)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        if isinstance(node.ctx, ast.Load):
            source_kind = self._source_kind(node)
            if source_kind:
                self._add_source(node, source_kind)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> Any:
        kind = "elif" if isinstance(self.parents.get(node), ast.If) and node in self.parents[node].orelse else "if"
        self._add_control(node.test, kind)
        self._add_guard_region(node)
        if self._is_authorization_decision(node.test):
            self._add_sink(node.test, "authorization_decision", "authz", _loaded_names(node.test), "medium")
        self.visit(node.test)

        cond_val = _eval_python_constant(node.test, self._const_env)
        if cond_val is not _UNKNOWN:
            branch = node.body if bool(cond_val) else node.orelse
            for stmt in branch:
                self.visit(stmt)
            return

        snapshot = self._snapshot_state()
        self._branch_depth += 1
        for stmt in node.body:
            self.visit(stmt)
        then_state = self._snapshot_state()

        self._restore_state(snapshot)
        for stmt in node.orelse:
            self.visit(stmt)
        else_state = self._snapshot_state()
        self._branch_depth -= 1

        then_const, then_lists, then_html, then_formatted, then_rand, then_types = then_state
        else_const, else_lists, else_html, else_formatted, else_rand, else_types = else_state
        self._const_env = {
            key: value for key, value in then_const.items() if key in else_const and else_const[key] == value and value is not _UNKNOWN
        }
        self._list_envs = {
            key: list(value) for key, value in snapshot[1].items() if then_lists.get(key) == value and else_lists.get(key) == value
        }
        self._html_vars = then_html | else_html
        self._formatted_str_vars = then_formatted | else_formatted
        self._weak_rand_vars = {**else_rand, **then_rand}
        self._var_types = {**else_types, **then_types}

    def visit_Match(self, node: ast.Match) -> Any:
        subject_val = _eval_python_constant(node.subject, self._const_env)
        if subject_val is not _UNKNOWN:
            for case in node.cases:
                if case.guard is None and self._match_constant_pattern(case.pattern, subject_val):
                    for stmt in case.body:
                        self.visit(stmt)
                    return
        snapshot = self._snapshot_state()
        self._branch_depth += 1
        all_html = set(self._html_vars)
        all_formatted = set(self._formatted_str_vars)
        all_rand = dict(self._weak_rand_vars)
        for case in node.cases:
            self._restore_state(snapshot)
            for stmt in case.body:
                self.visit(stmt)
            all_html |= self._html_vars
            all_formatted |= self._formatted_str_vars
            all_rand.update(self._weak_rand_vars)
        self._branch_depth -= 1
        self._const_env = {k: v for k, v in snapshot[0].items() if k.split(".", 1)[0].split("[", 1)[0] not in _assigned_target_roots(node)}
        self._list_envs = {}
        self._html_vars = all_html
        self._formatted_str_vars = all_formatted
        self._weak_rand_vars = all_rand

    @staticmethod
    def _match_constant_pattern(pattern: ast.pattern, value: Any) -> bool:
        if isinstance(pattern, ast.MatchAs):
            return pattern.pattern is None or _SemanticAnalyzer._match_constant_pattern(pattern.pattern, value)
        if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
            return pattern.value.value == value
        if isinstance(pattern, ast.MatchSingleton):
            return pattern.value is value
        if isinstance(pattern, ast.MatchOr):
            return any(_SemanticAnalyzer._match_constant_pattern(sub, value) for sub in pattern.patterns)
        return False

    def _extract_guard_spec(self, test: ast.AST) -> tuple[str, list[str], list[str], bool, bool] | None:
        all_inj = [
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
        condition = test
        validation_passes = True
        while isinstance(condition, ast.UnaryOp) and isinstance(condition.op, ast.Not):
            validation_passes = not validation_passes
            condition = condition.operand

        if isinstance(condition, ast.Call):
            sanitizer = self._sanitizer_kind(condition)
            if sanitizer is not None:
                sanitizer_kind, applies_to = sanitizer
                if sanitizer_kind in {"url_validation", "type_validation", "authorization_guard"}:
                    inputs = list(
                        dict.fromkeys(
                            name
                            for value in [*condition.args, *(keyword.value for keyword in condition.keywords)]
                            for name in self._value_sources(value)
                        )
                    )
                    if inputs:
                        return sanitizer_kind, applies_to, inputs, validation_passes, False
            resolved = self._resolved_name(condition.func).lower()
            last = resolved.rsplit(".", 1)[-1]
            if (resolved.startswith(("re.", "regex.")) or isinstance(condition.func, ast.Attribute)) and last in {
                "match",
                "fullmatch",
                "search",
            }:
                if resolved.startswith(("re.", "regex.")) and len(condition.args) >= 2:
                    inputs = self._value_sources(condition.args[1])
                    if inputs:
                        return "validation_guard", all_inj, inputs, validation_passes, False
            if isinstance(condition.func, ast.Attribute) and condition.func.attr in {"startswith", "is_relative_to"}:
                recv = condition.func.value
                recv_text = _node_text(recv).lower()
                recv_path = _access_path(recv) or ""
                if (
                    self._is_path_expr(recv)
                    or self._var_types.get(recv_path) == "path"
                    or any(tok in recv_text for tok in ("path", "resolve(", "abspath(", "realpath(", "normpath("))
                ):
                    inputs = self._value_sources(recv)
                    if inputs:
                        return "path_validation", ["file_path"], inputs, validation_passes, False
            if isinstance(condition.func, ast.Attribute) and condition.func.attr in {
                "isdigit",
                "isnumeric",
                "isdecimal",
                "isalnum",
                "isalpha",
            }:
                inputs = self._value_sources(condition.func.value)
                if inputs:
                    return "type_validation", all_inj, inputs, validation_passes, False
            if last == "isinstance" and len(condition.args) >= 2 and _node_text(condition.args[1]) in {"int", "float", "UUID"}:
                inputs = self._value_sources(condition.args[0])
                if inputs:
                    return "type_validation", all_inj, inputs, validation_passes, False
            return None

        if isinstance(condition, ast.Compare) and len(condition.ops) == 1 and len(condition.comparators) == 1:
            op = condition.ops[0]
            left = condition.left
            right = condition.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)) and not isinstance(left, ast.Constant):
                right_text = _node_text(right).lower()
                is_allowlist = (
                    isinstance(right, (ast.Tuple, ast.List, ast.Set))
                    and bool(right.elts)
                    and all(isinstance(elt, ast.Constant) for elt in right.elts)
                ) or bool(re.search(r"\b(?:allow\w*|valid\w*|safe\w*|permit\w*|choice\w*|option\w*|whitelist\w*)\b", right_text))
                if is_allowlist:
                    inputs = self._value_sources(left)
                    if inputs:
                        passes = validation_passes if isinstance(op, ast.In) else (not validation_passes)
                        return "validation_guard", all_inj, inputs, passes, False
            if isinstance(op, (ast.Eq, ast.NotEq)):
                target_node: ast.AST | None = None
                if isinstance(right, ast.Constant) and isinstance(right.value, (str, int, float)) and not isinstance(right.value, bool):
                    if isinstance(left, ast.Name):
                        target_node = left
                elif isinstance(left, ast.Constant) and isinstance(left.value, (str, int, float)) and not isinstance(left.value, bool):
                    if isinstance(right, ast.Name):
                        target_node = right
                if target_node is not None:
                    inputs = self._value_sources(target_node)
                    if inputs:
                        passes = validation_passes if isinstance(op, ast.Eq) else (not validation_passes)
                        return "constant_equality_guard", all_inj, inputs, passes, False
        return None

    def _add_guard_region(self, node: ast.If) -> None:
        spec = self._extract_guard_spec(node.test)
        if spec is None:
            return
        sanitizer_kind, applies_to, inputs, validation_passes, reject_and_terminate = spec

        protected: tuple[int, int] | None = None
        if reject_and_terminate:
            if self._block_terminates(node.body):
                protected = self._guard_continuation(node)
        elif validation_passes and node.body:
            protected = (node.body[0].lineno, int(getattr(node.body[-1], "end_lineno", node.body[-1].lineno)))
        elif not validation_passes and self._block_terminates(node.body):
            protected = self._guard_continuation(node)
        if protected is None:
            return
        start, end = protected
        anchor = _range_anchor(self.source_file, start, end, f"guard:{sanitizer_kind}")
        expression = _node_text(node.test)
        self.result.sanitizers.append(
            SanitizerFact(
                id=stable_id(
                    "sanitizer",
                    self.source_file.file.path,
                    node.lineno,
                    f"guard:{sanitizer_kind}:{self.scope_id}:{start}:{end}:{expression}",
                ),
                kind=sanitizer_kind,
                expression=f"guarded-region: {expression}",
                anchor=anchor,
                confidence="high" if sanitizer_kind in {"html_encoding", "url_validation", "path_validation"} else "medium",
                variables=inputs,
                input_variables=inputs,
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
                applies_to_sink_kinds=applies_to,
            )
        )

    @staticmethod
    def _block_terminates(statements: list[ast.stmt]) -> bool:
        return bool(statements) and isinstance(statements[-1], (ast.Return, ast.Raise))

    def _guard_continuation(self, node: ast.If) -> tuple[int, int] | None:
        parent = self.parents.get(node)
        if parent is None:
            return None
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(parent, attr, None)
            if isinstance(block, list) and node in block:
                index = block.index(node)
                following = block[index + 1 :]
                if not following:
                    return None
                return following[0].lineno, int(getattr(following[-1], "end_lineno", following[-1].lineno))
        return None

    def visit_For(self, node: ast.For) -> Any:
        self._visit_for_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self._visit_for_loop(node)

    def _visit_for_loop(self, node: ast.For | ast.AsyncFor) -> None:
        self._add_control(node.iter, "for", region_node=node)
        for root in _assigned_target_roots(node):
            self._invalidate_const_target(root)
        iter_sources = self._value_sources(node.iter)
        if isinstance(node.iter, ast.Name) and node.iter.id in self._list_envs:
            slot_sources = [name for _val, src, _wr in self._list_envs[node.iter.id] for name in src]
            iter_sources = list(dict.fromkeys([*iter_sources, *slot_sources]))
        for target in _target_names(node.target):
            self._add_assignment(node, target, iter_sources, _node_text(node.iter), safe_overwrite=False)
            if weak := self._expr_weak_rand(node.iter):
                self._weak_rand_vars[target] = weak
        self.visit(node.iter)
        self.visit(node.target)
        self._branch_depth += 1
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        self._branch_depth -= 1

    def visit_While(self, node: ast.While) -> Any:
        self._add_control(node.test, "while", region_node=node)
        cond_val = _eval_python_constant(node.test, self._const_env)
        if cond_val is not _UNKNOWN and not bool(cond_val):
            return
        for root in _assigned_target_roots(node):
            self._invalidate_const_target(root)
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_With(self, node: ast.With) -> Any:
        self._visit_with_stmt(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self._visit_with_stmt(node)

    def _visit_with_stmt(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                sources = self._value_sources(item.context_expr)
                for target in _target_names(item.optional_vars):
                    self._add_assignment(node, target, sources, _node_text(item.context_expr), safe_overwrite=False)
                    self._invalidate_const_target(target)
                self.visit(item.optional_vars)
        for stmt in node.body:
            self.visit(stmt)

    def visit_Try(self, node: ast.Try) -> Any:
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> Any:
        anchor_node = node.type or node
        self._add_control(anchor_node, "catch")
        self.generic_visit(node)

    def _add_control(self, node: ast.AST, kind: str, *, region_node: ast.AST | None = None) -> None:
        expression = _node_text(node)
        self.result.control_flows.append(
            ControlFlowFact(
                id=stable_id("cfg", self.source_file.file.path, node.lineno, f"{kind}:{self.scope_id}:{expression}"),
                kind=kind,  # type: ignore[arg-type]
                condition=expression,
                variables=_loaded_names(node),
                anchor=_anchor(self.source_file, region_node or node, kind),
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
            )
        )

    def _add_source(self, node: ast.AST, kind: str) -> None:
        expression = _node_text(node)
        variables = self._assigned_targets(node)
        if not variables:
            if isinstance(node, ast.Call):
                variables = [self._call_result(node)]
            else:
                path = _access_path(node)
                variables = [path] if path else []
        self.result.sources.append(
            SourceFact(
                id=stable_id("source", self.source_file.file.path, node.lineno, f"{kind}:{node.col_offset}:{expression}"),
                kind=kind,
                expression=expression,
                anchor=_anchor(self.source_file, node, kind),
                confidence="high" if kind in {"http_query", "http_body", "http_path"} else "medium",
                variables=variables,
                input_variables=_loaded_names(node),
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
            )
        )

    def _add_sink(
        self,
        node: ast.AST,
        kind: str,
        vuln_class: str,
        variables: list[str],
        confidence: str,
    ) -> None:
        taxonomy_id, cwe_ids = TAXONOMY_BY_SINK[kind]
        expression = _node_text(node)
        self.result.sinks.append(
            SinkFact(
                id=stable_id("sink", self.source_file.file.path, node.lineno, f"{kind}:{node.col_offset}:{expression}"),
                kind=kind,
                vuln_class=vuln_class,  # type: ignore[arg-type]
                expression=expression,
                anchor=_anchor(self.source_file, node, kind),
                confidence=confidence,  # type: ignore[arg-type]
                variables=variables,
                enclosing_function_id=self.scope_id,
                analysis_method="ast",
                taxonomy_id=taxonomy_id,
                cwe_ids=cwe_ids,
            )
        )

    def _add_weak_random_sink(self, node: ast.AST, prng_name: str) -> None:
        del prng_name
        self._add_sink(node, "weak_random", "auth", [], "high")

    def _assigned_targets(self, node: ast.AST) -> list[str]:
        origin = node
        current = node
        while current in self.parents:
            parent = self.parents[current]
            if isinstance(parent, ast.Assign) and current is parent.value:
                if (
                    len(parent.targets) == 1
                    and isinstance(parent.value, (ast.Tuple, ast.List))
                    and isinstance(parent.targets[0], (ast.Tuple, ast.List))
                ):
                    for index, value_item in enumerate(parent.value.elts):
                        if index >= len(parent.targets[0].elts):
                            break
                        if any(descendant is origin for descendant in ast.walk(value_item)):
                            return _target_names(parent.targets[0].elts[index])
                return list(dict.fromkeys(name for target in parent.targets for name in _target_names(target)))
            if isinstance(parent, ast.AnnAssign) and current is parent.value:
                return _target_names(parent.target)
            if isinstance(parent, ast.AugAssign) and current is parent.value:
                return _target_names(parent.target)
            if isinstance(parent, ast.NamedExpr) and current is parent.value:
                return _target_names(parent.target)
            if isinstance(parent, ast.stmt):
                break
            current = parent
        return []

    def _source_kind(self, node: ast.AST) -> str | None:
        text = _node_text(node)
        lowered = text.lower()
        if re.search(r"\b(?:request|req|ctx|c)\.(?:args|query|query_params|values|get|query_string|full_path)(?:\.|\[|$)", lowered):
            return "http_query"
        if re.search(r"\b(?:request|req|ctx|c)\.(?:form|json|data|post|body|stream)(?:\.|\[|$)", lowered) or any(
            marker in lowered for marker in ("request.get_json(", "request.get_data(", "req.get_json(", "req.get_data(")
        ):
            return "http_body"
        if re.search(r"\b(?:request|req|ctx|c)\.(?:view_args|path_params|params|path|url|base_url)(?:\.|\[|$)", lowered):
            return "http_path"
        if re.search(r"\b(?:request|req|ctx|c)\.(?:headers|header|environ|meta)(?:\.|\[|$)", lowered):
            return "http_header"
        if "request.cookies" in lowered or "req.cookies" in lowered or re.search(r"\bsession(?:\.|\[)", lowered):
            return "cookie"
        if "request.files" in lowered or "uploadedfile" in lowered:
            return "file_upload"
        if any(marker in lowered for marker in ("websocket.receive", "websocket.recv", "ws.receive", "ws.recv")):
            return "websocket_message"
        return None

    def _sink_kind(self, node: ast.Call) -> tuple[str, str, list[str], str] | None:
        raw = _qualified_name(node.func).lower()
        resolved = self._resolved_name(node.func).lower()
        last = (resolved or raw).rsplit(".", 1)[-1]
        positional = [self._value_sources(arg) for arg in node.args]
        keywords = {keyword.arg: self._value_sources(keyword.value) for keyword in node.keywords if keyword.arg}
        receiver_sources = self._value_sources(node.func.value) if isinstance(node.func, ast.Attribute) else []
        names_set = {raw, resolved}

        def argument(index: int = 0, *keyword_names: str) -> list[str]:
            if index < len(positional):
                return positional[index]
            for keyword_name in keyword_names:
                if keyword_name in keywords:
                    return keywords[keyword_name]
            return []

        if last in {"execute", "executemany", "executescript", "executequery", "execsql", "raw", "createquery", "queryrow"} or (
            resolved in {"sqlalchemy.text", "sqlalchemy.sql.text", "django.db.models.expressions.rawsql"}
        ):
            return "raw_sql", "injection", argument(0, "statement", "query", "sql"), "high"
        if names_set & {
            "os.system",
            "os.popen",
            "os.execl",
            "os.execle",
            "os.execlp",
            "os.execlpe",
            "os.execv",
            "os.execve",
            "os.execvp",
            "os.execvpe",
            "os.spawnl",
            "os.spawnle",
            "os.spawnlp",
            "os.spawnlpe",
            "os.spawnv",
            "os.spawnve",
            "os.spawnvp",
            "os.spawnvpe",
            "os.posix_spawn",
            "os.posix_spawnp",
            "subprocess.run",
            "subprocess.popen",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
            "asyncio.create_subprocess_shell",
            "asyncio.create_subprocess_exec",
            "pty.spawn",
        }:
            return "command_execution", "injection", argument(0, "args", "command", "cmd", "file"), "high"
        if resolved in {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"} or raw in {
            "eval",
            "exec",
            "compile",
        }:
            return "code_evaluation", "injection", argument(0, "source"), "high"
        if last == "send_from_directory" or resolved in {"flask.send_from_directory", "werkzeug.utils.send_from_directory"}:
            target_vars = (
                argument(1, "path", "filename") if len(positional) >= 2 or "path" in keywords or "filename" in keywords else argument(0)
            )
            return "file_path", "injection", target_vars, "high"
        if last == "open" and isinstance(node.func, ast.Attribute) and self._is_path_expr(node.func.value):
            return "file_path", "injection", receiver_sources, "medium"
        if last in {"open", "send_file"} or names_set & {
            "pathlib.path",
            "pathlib.purepath",
            "os.open",
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "os.mkdir",
            "os.makedirs",
            "os.rename",
            "os.replace",
            "os.stat",
            "os.lstat",
            "os.access",
            "os.listdir",
            "os.scandir",
            "os.path.exists",
            "os.path.isfile",
            "os.path.isdir",
            "os.path.lexists",
            "io.open",
            "codecs.open",
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.move",
            "shutil.rmtree",
            "tarfile.open",
            "zipfile.zipfile",
        }:
            extra = (
                argument(1, "dst")
                if resolved in {"os.rename", "os.replace", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move"}
                else []
            )
            return "file_path", "injection", list(dict.fromkeys([*argument(0, "file", "filename", "path", "src"), *extra])), "medium"
        if last in {"read_text", "write_text", "read_bytes", "write_bytes", "exists", "is_file", "is_dir", "stat", "lstat"} and isinstance(
            node.func, ast.Attribute
        ):
            recv_path = _access_path(node.func.value) or ""
            if self._is_path_expr(node.func.value) or self._var_types.get(recv_path) == "path":
                return "file_path", "injection", receiver_sources, "medium"
        if (
            names_set
            & {
                "pickle.loads",
                "pickle.load",
                "yaml.unsafe_load",
                "yaml.full_load",
                "yaml.load_all",
                "marshal.loads",
                "dill.loads",
                "cloudpickle.loads",
                "jsonpickle.decode",
                "shelve.open",
                "pandas.read_pickle",
                "joblib.load",
                "torch.load",
            }
            or last in {"deserialize", "unserialize"}
            or ("yaml.load" in names_set and not self._is_safe_yaml_load(node))
        ):
            if "torch.load" in names_set and self._keyword_bool(node, "weights_only") is True:
                return None
            return "deserialization", "injection", argument(0, "data", "payload", "stream", "string"), "high"
        if names_set & {
            "ldap.search_s",
            "ldap.search_ext_s",
            "ldap.search_st",
            "ldap.search_ext",
            "ldap.simple_bind_s",
            "ldap3.connection.search",
        } or (
            last == "search"
            and self._has_ldap_import
            and not raw.startswith(("re.", "regex."))
            and (
                "search_base" in keywords
                or "search_filter" in keywords
                or len(positional) >= 2
                or (isinstance(node.func, ast.Attribute) and self._var_types.get(_access_path(node.func.value) or "") == "ldap")
            )
        ):
            vars_ldap = list(dict.fromkeys([*argument(0, "search_base", "base"), *argument(1, "search_filter", "filterstr")]))
            return "ldap_injection", "injection", vars_ldap, "high"
        if resolved in {"lxml.etree.xpath", "lxml.etree.etxpath"} or (isinstance(node.func, ast.Attribute) and last == "xpath"):
            return "xpath_injection", "injection", argument(0, "path", "_path"), "high"
        if resolved == "elementpath.select" or raw.endswith("elementpath.select"):
            return "xpath_injection", "injection", argument(1, "path"), "high"
        if (
            isinstance(node.func, ast.Attribute)
            and last in {"find", "findall", "findtext", "iterfind"}
            and (self._has_xml_import or self._has_defusedxml_import)
            and self._var_types.get(_access_path(node.func.value) or "") == "xml"
        ):
            return "xpath_injection", "injection", argument(0, "path"), "medium"
        if not self._has_defusedxml_import and (
            names_set & _XML_PARSER_CALLEES
            or (
                self._has_xml_import
                and last in {"fromstring", "parse", "parsestring", "xml"}
                and not raw.startswith(("json.", "yaml.", "urllib.", "argparse."))
            )
        ):
            if not self._has_safe_xml_parser_kw(node):
                return "xxe", "injection", argument(0, "text", "source", "filename_or_file"), "high"
        if names_set & {
            "render_template_string",
            "flask.render_template_string",
            "markupsafe.markup",
            "jinja2.template",
        }:
            return "html_output", "xss", argument(0, "source", "html", "string"), "high"
        if names_set & {
            "flask.make_response",
            "make_response",
            "flask.response",
            "werkzeug.wrappers.response",
            "django.http.httpresponse",
            "fastapi.responses.htmlresponse",
            "starlette.responses.htmlresponse",
            "aiohttp.web.response",
        }:
            if not self._is_non_html_response(node):
                variables = list(dict.fromkeys([*argument(0, "rv", "response", "content", "body", "text")]))
                return "html_output", "xss", variables, "medium"
        if names_set & {
            "flask.redirect",
            "django.shortcuts.redirect",
            "werkzeug.utils.redirect",
            "bottle.redirect",
            "starlette.responses.redirectresponse",
            "fastapi.responses.redirectresponse",
            "aiohttp.web.httpfound",
            "aiohttp.web.httpseeother",
            "aiohttp.web.httpmovedpermanently",
            "aiohttp.web.httptemporaryredirect",
            "aiohttp.web.httppermanentredirect",
        } or raw in {"self.redirect", "redirect"}:
            return "open_redirect", "ssrf", argument(0, "location", "url", "to"), "high"
        if names_set & {"urllib.request.urlopen", "requests.request", "httpx.request", "aiohttp.request"}:
            url_index = 1 if (resolved or raw).endswith(".request") and len(positional) > 1 else 0
            return "external_request", "ssrf", argument(url_index, "url"), "high"
        if any(candidate.startswith(("requests.", "httpx.", "aiohttp.")) for candidate in names_set) and last in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
        }:
            return "external_request", "ssrf", argument(0, "url"), "high"
        if last in {"authenticate", "login_user", "verify_password", "decode_token", "verify_token"}:
            variables = list(dict.fromkeys(name for names in [*positional, *keywords.values()] for name in names))
            return "auth_primitive", "auth", variables, "medium"
        return None

    def _check_semantic_call_sinks(
        self,
        node: ast.Call,
        argument_sources: list[list[str]],
        keyword_sources: dict[str, list[str]],
    ) -> None:
        raw = _qualified_name(node.func).lower()
        resolved = self._resolved_name(node.func).lower()
        names_set = {raw, resolved}
        last = (resolved or raw).rsplit(".", 1)[-1]
        fn_name = self._function_stack[-1].name if self._function_stack else ""
        stmt_text = _node_text(node)

        # 1. Weak hash algorithms (MD2/MD4/MD5/SHA1)
        is_weak_hash = False
        if names_set & {
            "hashlib.md5",
            "hashlib.sha1",
            "crypto.hash.md5.new",
            "crypto.hash.md4.new",
            "crypto.hash.sha.new",
            "crypto.hash.sha1.new",
            "cryptodome.hash.md5.new",
            "cryptodome.hash.md4.new",
            "cryptodome.hash.sha.new",
            "cryptodome.hash.sha1.new",
            "cryptography.hazmat.primitives.hashes.md5",
            "cryptography.hazmat.primitives.hashes.sha1",
        }:
            is_weak_hash = self._keyword_bool(node, "usedforsecurity") is not False
        elif "hashlib.new" in names_set and node.args:
            alg = _eval_python_constant(node.args[0], self._const_env)
            if isinstance(alg, str) and alg.strip().lower() in _WEAK_HASH_ALGOS:
                is_weak_hash = self._keyword_bool(node, "usedforsecurity") is not False
        elif "hmac.new" in names_set:
            digest = next((kw.value for kw in node.keywords if kw.arg == "digestmod"), node.args[2] if len(node.args) >= 3 else None)
            if digest is not None:
                digest_val = _eval_python_constant(digest, self._const_env)
                digest_name = self._resolved_name(digest).lower()
                if (isinstance(digest_val, str) and digest_val.strip().lower() in _WEAK_HASH_ALGOS) or digest_name in {
                    "hashlib.md5",
                    "hashlib.sha1",
                }:
                    is_weak_hash = True

        if is_weak_hash:
            is_checksum_only = (
                bool(_CHECKSUM_NAME_RE.search(fn_name))
                and not self._in_route_scope
                and not _has_security_context(stmt_text)
                and not self._assigned_targets(node)
                and not self.result.sources
            )
            if not is_checksum_only:
                self._add_sink(node, "weak_hash", "auth", [], "high")

        # 2. Weak ciphers and legacy TLS protocols
        if names_set & _WEAK_CIPHER_CALLEES:
            self._add_sink(node, "weak_cipher", "auth", [], "high")
        elif names_set & {"crypto.cipher.aes.new", "cryptodome.cipher.aes.new"}:
            mode_arg = next((kw.value for kw in node.keywords if kw.arg == "mode"), node.args[1] if len(node.args) >= 2 else None)
            if mode_arg is not None and "mode_ecb" in self._resolved_name(mode_arg).lower():
                self._add_sink(node, "weak_cipher", "auth", [], "high")
        elif "ssl.sslcontext" in names_set and node.args:
            proto_name = self._resolved_name(node.args[0]).lower()
            if proto_name in _WEAK_SSL_PROTOCOLS:
                self._add_sink(node, "weak_cipher", "auth", [], "high")

        # 3. Weak random PRNG usage
        weak_prng = self._direct_weak_random_name(node)
        if weak_prng:
            assigned = self._assigned_targets(node)
            parent_text = self._enclosing_statement_text(node)
            if (
                _has_security_context(parent_text)
                or _has_security_context(fn_name)
                or any(_has_security_context(target) for target in assigned)
                or self._is_inside_security_sink_call(node)
            ):
                self._add_weak_random_sink(node, weak_prng)

        # 4. Propagation of weak random variables into security sinks
        all_arg_vars = [name for group in [*argument_sources, *keyword_sources.values()] for name in group]
        matched_weak = next((self._weak_rand_vars[var] for var in all_arg_vars if var in self._weak_rand_vars), None)
        if matched_weak and (last in {"set_cookie", "hexdigest", "digest", "md5", "sha1", "sha256"} or _has_security_context(stmt_text)):
            self._add_weak_random_sink(node, matched_weak[1])

        # 5. Insecure cookie (missing or False secure=True)
        if last == "set_cookie":
            secure_kw = next((kw.value for kw in node.keywords if kw.arg == "secure"), None)
            if secure_kw is None:
                self._add_sink(node, "insecure_cookie", "auth", [], "medium")
            else:
                secure_val = _eval_python_constant(secure_kw, self._const_env)
                if secure_val is False or (secure_val is _UNKNOWN and "false" in _node_text(secure_kw).lower()):
                    self._add_sink(node, "insecure_cookie", "auth", [], "high")

    def _enclosing_statement_text(self, node: ast.AST) -> str:
        current = node
        while current in self.parents:
            parent = self.parents[current]
            if isinstance(parent, ast.stmt):
                return _node_text(parent)
            current = parent
        return _node_text(node)

    def _is_inside_security_sink_call(self, node: ast.AST) -> bool:
        current = node
        while current in self.parents:
            parent = self.parents[current]
            if isinstance(parent, ast.Call):
                callee = (self._resolved_name(parent.func) or _qualified_name(parent.func)).lower()
                if callee.rsplit(".", 1)[-1] in {"set_cookie", "hexdigest", "digest", "md5", "sha1", "sha256"}:
                    return True
            if isinstance(parent, ast.stmt):
                return False
            current = parent
        return False

    def _direct_weak_random_name(self, node: ast.Call) -> str | None:
        resolved = self._resolved_name(node.func).lower()
        raw = _qualified_name(node.func).lower()
        for candidate in (resolved, raw):
            if candidate.startswith("random.") and candidate.split(".", 1)[1] in _WEAK_RANDOM_METHODS:
                return candidate
        if isinstance(node.func, ast.Attribute) and node.func.attr.lower() in _WEAK_RANDOM_METHODS:
            recv = node.func.value
            recv_path = _access_path(recv)
            if recv_path and self._var_types.get(recv_path) == "weak_random_obj":
                return f"random.{node.func.attr.lower()}"
            if isinstance(recv, ast.Call) and self._resolved_name(recv.func).lower() == "random.random":
                return f"random.{node.func.attr.lower()}"
        return None

    def _expr_weak_rand(self, node: ast.AST) -> tuple[int, str] | None:
        if self._is_csprng_expr(node):
            return None
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                if name := self._direct_weak_random_name(item):
                    return item.lineno, name
        for name in self._value_sources(node):
            if name in self._weak_rand_vars:
                return self._weak_rand_vars[name]
        return None

    def _is_csprng_expr(self, node: ast.AST) -> bool:
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                resolved = self._resolved_name(item.func).lower()
                if resolved.startswith(_SAFE_CSPRNG_PREFIXES) or "systemrandom" in resolved:
                    return True
                if isinstance(item.func, ast.Attribute):
                    recv_path = _access_path(item.func.value)
                    if recv_path and self._var_types.get(recv_path) == "safe_random_obj":
                        return True
        return False

    def _is_path_expr(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            path = _access_path(node) or ""
            if self._var_types.get(path) == "path":
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._is_path_expr(node.left)
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            return self._is_path_expr(node.value)
        if isinstance(node, ast.Call):
            resolved = self._resolved_name(node.func).lower()
            if resolved in {"pathlib.path", "pathlib.purepath"} or resolved.endswith((".path", ".purepath")):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "resolve",
                "absolute",
                "expanduser",
                "joinpath",
                "with_name",
                "with_suffix",
                "with_stem",
            }:
                return self._is_path_expr(node.func.value)
        return "path(" in _node_text(node).lower()

    def _infer_expr_type(self, node: ast.AST) -> str | None:
        if self._is_path_expr(node):
            return "path"
        if not isinstance(node, ast.Call):
            return None
        resolved = self._resolved_name(node.func).lower()
        last = resolved.rsplit(".", 1)[-1]
        if resolved == "random.random" and isinstance(node.func, ast.Attribute) and node.func.attr == "Random":
            return "weak_random_obj"
        if "systemrandom" in resolved:
            return "safe_random_obj"
        if resolved in {"configparser.configparser", "configparser.rawconfigparser", "configparser.safeconfigparser"}:
            return "configparser"
        if resolved in {"io.stringio", "io.bytesio", "stringio.stringio"}:
            return "stringio"
        if resolved in {"ldap3.connection", "ldap.initialize"} or (self._has_ldap_import and last == "get_connection"):
            return "ldap"
        if (self._has_xml_import or self._has_defusedxml_import) and (
            resolved in _XML_PARSER_CALLEES or last in {"fromstring", "parse", "parsestring", "getroot"}
        ):
            return "xml"
        return None

    def _is_session_expr(self, node: ast.AST) -> bool:
        resolved = self._resolved_name(node).lower()
        raw = _access_path(node) or ""
        return (
            resolved in {"flask.session", "session"}
            or raw.lower() in {"request.session", "flask.session"}
            or (raw == "session" and "flask" in " ".join(self.import_aliases.values()).lower())
        )

    def _is_session_subscript(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Subscript) and self._is_session_expr(node.value)

    def _keyword_bool(self, node: ast.Call, name: str) -> bool | None:
        for kw in node.keywords:
            if kw.arg == name:
                val = _eval_python_constant(kw.value, self._const_env)
                if isinstance(val, bool):
                    return val
        return None

    def _is_safe_yaml_load(self, node: ast.Call) -> bool:
        loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), node.args[1] if len(node.args) >= 2 else None)
        if loader is None:
            return False
        name = (self._resolved_name(loader) or _qualified_name(loader)).lower()
        return any(safe in name for safe in ("safeloader", "csafeloader", "baseloader"))

    def _has_safe_xml_parser_kw(self, node: ast.Call) -> bool:
        parser = next((kw.value for kw in node.keywords if kw.arg == "parser"), node.args[1] if len(node.args) >= 2 else None)
        if parser is None or not isinstance(parser, ast.Call):
            return False
        return self._keyword_bool(parser, "resolve_entities") is False

    def _is_non_html_response(self, node: ast.Call) -> bool:
        if node.args and isinstance(node.args[0], ast.Call):
            callee = (self._resolved_name(node.args[0].func) or _qualified_name(node.args[0].func)).lower()
            if callee.rsplit(".", 1)[-1] == "jsonify":
                return True
        for kw in node.keywords:
            if kw.arg in {"mimetype", "content_type"}:
                val = _eval_python_constant(kw.value, self._const_env)
                if isinstance(val, str) and ("json" in val.lower() or "text/plain" in val.lower() or "octet-stream" in val.lower()):
                    return True
        return False

    def _sanitizer_kind(self, node: ast.Call) -> tuple[str, list[str]] | None:
        lowered = _qualified_name(node.func).lower()
        resolved = self._resolved_name(node.func).lower()
        last = (resolved or lowered).rsplit(".", 1)[-1]
        if last in {"escape", "escape_for_html", "escapehtml", "htmlspecialchars", "encodeforhtml", "sanitizehtml"} or resolved in {
            "bleach.clean",
            "nh3.clean",
            "html.escape",
            "cgi.escape",
            "markupsafe.escape",
            "django.utils.html.escape",
            "django.utils.html.format_html",
        }:
            return "html_encoding", ["html_output"]
        if last in {"int", "float", "uuid", "parseint"} or resolved in {"uuid.uuid", "uuid.uuid4"}:
            return "type_validation", [
                "raw_sql",
                "command_execution",
                "file_path",
                "external_request",
                "open_redirect",
                "ldap_injection",
                "xpath_injection",
            ]
        if (
            resolved in {"os.path.basename", "ntpath.basename", "posixpath.basename", "werkzeug.utils.secure_filename"}
            or last == "secure_filename"
        ):
            return "path_sanitization", ["file_path"]
        if resolved in {"shlex.quote", "pipes.quote"}:
            return "shell_escaping", ["command_execution"]
        if last in {"escape_filter_chars", "escape_dn_chars"}:
            return "ldap_escaping", ["ldap_injection"]
        if last in {"escape_xpath"}:
            return "xpath_escaping", ["xpath_injection"]
        if last in {"isallowedhost", "validate_url", "validateurl", "is_safe_url", "issafeurl"}:
            return "url_validation", ["external_request", "open_redirect"]
        if last in {"requireauth", "requireuser", "requireadmin", "authorize", "haspermission"}:
            return "authorization_guard", ["authorization_decision"]
        return None

    def _is_authorization_decision(self, node: ast.AST) -> bool:
        text = _node_text(node).lower()
        markers = ("is_admin", "isadmin", "role", "permission", "owner", "tenant", "user_id", "account_id", "authorize")
        return any(marker in text for marker in markers)

    def _expr_has_html(self, node: ast.AST) -> bool:
        return "<" in _node_text(node) and bool(isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call, ast.Constant)))

    def _is_html_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return "<" in _node_text(node) and bool(_loaded_names(node))
        if not isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return False
        return "<" in _node_text(node) and bool(_loaded_names(node))

    def _is_formatted_str_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return bool(node.args or node.keywords)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            has_str = (
                (isinstance(node.left, ast.Constant) and isinstance(node.left.value, str))
                or (isinstance(node.right, ast.Constant) and isinstance(node.right.value, str))
                or self._is_formatted_str_expr(node.left)
                or self._is_formatted_str_expr(node.right)
            )
            return has_str and bool(_loaded_names(node))
        return False

    def _is_non_html_return(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.Dict, ast.List, ast.Set)):
            return True
        if isinstance(node, ast.Call):
            callee = (self._resolved_name(node.func) or _qualified_name(node.func)).lower()
            last = callee.rsplit(".", 1)[-1]
            if last in {"jsonify", "dumps"} or callee in {"json.dumps"}:
                return True
            if self._is_non_html_response(node):
                return True
        return False
