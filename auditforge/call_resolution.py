"""Indexed, conservative cross-file call resolution shared by graph and taint analysis."""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from .models import CallSiteFact, FunctionFact, ImportFact


def resolution_models_from_diagnostics(diagnostics: Mapping[str, Any] | None) -> dict[str, list[Any]]:
    """Merge language-specific receiver models for the shared resolver."""

    if not isinstance(diagnostics, Mapping):
        return {}
    explicit = diagnostics.get("symbol_resolution")
    if isinstance(explicit, Mapping):
        return {key: list(value) for key, value in explicit.items() if isinstance(value, list)}
    output: dict[str, list[Any]] = defaultdict(list)
    for name in ("java_framework", "php_symbols", "python_symbols"):
        model = diagnostics.get(name)
        if not isinstance(model, Mapping):
            continue
        for key in ("receiver_types", "class_receiver_types", "implementation_types", "package_names"):
            value = model.get(key)
            if isinstance(value, list):
                output[key].extend(value)
    return dict(output)


class CallResolver:
    """Resolve a call target without repeatedly scanning every repository symbol.

    The resolver intentionally keeps the conservative uniqueness requirements of
    the original implementation.  Its indexes only narrow candidate sets; an
    ambiguous result is still not linked.
    """

    def __init__(
        self,
        functions: list[FunctionFact],
        imports: list[ImportFact] | None = None,
        framework_models: Mapping[str, Any] | None = None,
    ) -> None:
        self.functions = functions
        self.functions_by_file: dict[str, list[FunctionFact]] = defaultdict(list)
        self.functions_by_id: dict[str, FunctionFact] = {}
        self.functions_by_name: dict[str, list[FunctionFact]] = defaultdict(list)
        self.functions_by_file_name: dict[tuple[str, str], list[FunctionFact]] = defaultdict(list)
        self.methods_by_class_id: dict[tuple[str, str], list[FunctionFact]] = defaultdict(list)
        self.methods_by_class_name: dict[tuple[str, str], list[FunctionFact]] = defaultdict(list)
        self.functions_by_exact_key: dict[str, list[FunctionFact]] = defaultdict(list)
        self.functions_by_relative_module: dict[tuple[str, str], list[FunctionFact]] = defaultdict(list)
        self.functions_by_import_tail: dict[tuple[str, str], list[FunctionFact]] = defaultdict(list)
        self.imports_by_file: dict[str, list[ImportFact]] = defaultdict(list)
        self.receiver_types: dict[tuple[str, str, str], tuple[str, ...]] = {}
        self.receiver_reasons: dict[tuple[str, str, str], str] = {}
        self.class_receiver_types: dict[tuple[str, str], tuple[str, ...]] = {}
        self.class_receiver_reasons: dict[tuple[str, str], str] = {}
        self.implementation_types: dict[str, tuple[str, ...]] = {}
        package_names: dict[str, str] = {}
        for item in _objects((framework_models or {}).get("package_names")):
            file = _text(item.get("file"))
            package = _canonical_symbol(_text(item.get("package")))
            if file and package:
                package_names[file] = package

        # Java framework bindings are extracted after language parsing because
        # field injection and interface implementation are repository-level
        # facts.  Keep this optional and data-only so CallResolver remains
        # usable for every language and in unit tests without Spring.
        for item in _objects((framework_models or {}).get("receiver_types")):
            file = _text(item.get("file"))
            function_id = _text(item.get("function_id"))
            receiver = _text(item.get("receiver"))
            types = _type_names(item.get("types"))
            if file and function_id and receiver and types:
                key = (file, function_id, receiver.lstrip("$"))
                self.receiver_types[key] = tuple(types)
                self.receiver_reasons[key] = _model_resolution_reason(item)
        for item in _objects((framework_models or {}).get("class_receiver_types")):
            class_id = _text(item.get("class_id"))
            receivers = item.get("receivers")
            if not class_id or not isinstance(receivers, Mapping):
                continue
            for receiver, types in receivers.items():
                receiver_name = _text(receiver)
                type_names = _type_names(types)
                if receiver_name and type_names:
                    key = (class_id, receiver_name.lstrip("$"))
                    self.class_receiver_types[key] = tuple(type_names)
                    self.class_receiver_reasons[key] = _model_resolution_reason(item)
        for item in _objects((framework_models or {}).get("implementation_types")):
            interface = _canonical_symbol(_text(item.get("interface")))
            implementations = _type_names(item.get("implementations"))
            if interface and implementations:
                for key in _type_lookup_keys(interface):
                    self.implementation_types[key] = tuple(sorted(set(self.implementation_types.get(key, ())) | set(implementations)))

        for item in imports or []:
            self.imports_by_file[item.anchor.file].append(item)

        for function in functions:
            file = function.anchor.file
            name = function.name
            self.functions_by_file[file].append(function)
            self.functions_by_id[function.id] = function
            self.functions_by_name[name].append(function)
            self.functions_by_file_name[(file, name)].append(function)

            if function.class_id:
                self.methods_by_class_id[(function.class_id, name)].append(function)

            qualified = _canonical_symbol(function.qualified_name or name)
            if "." in qualified:
                class_name = qualified.rsplit(".", 1)[0]
                for type_name in _type_lookup_keys(class_name):
                    self.methods_by_class_name[(type_name, name)].append(function)

            module = _module_name(file) or package_names.get(file, "")
            exact_key = f"{module}.{qualified}" if module else qualified
            self.functions_by_exact_key[exact_key].append(function)
            if function.class_id:
                shorthand = f"{module}.{name}" if module else name
                self.functions_by_exact_key[shorthand].append(function)

            target = file.replace("\\", "/")
            target_without_extension = posixpath.splitext(target)[0]
            self.functions_by_relative_module[(target_without_extension, name)].append(function)
            owner = qualified.rsplit(".", 1)[0] if function.class_id and "." in qualified else ""
            for module_tail in {
                _simple_type(owner),
                posixpath.basename(target_without_extension),
                posixpath.basename(posixpath.dirname(target)),
            }:
                if module_tail:
                    self.functions_by_import_tail[(module_tail, name)].append(function)

    def resolve(self, call: CallSiteFact) -> FunctionFact | None:
        resolved = self.resolve_with_reason(call)
        return resolved[0] if resolved else None

    def resolve_with_reason(self, call: CallSiteFact) -> tuple[FunctionFact, str] | None:
        callee = _canonical_symbol(call.callee)
        simple = callee.rsplit(".", 1)[-1]
        caller = self.functions_by_id.get(call.enclosing_function_id or "")
        if caller is not None and caller.anchor.file != call.anchor.file:
            caller = None

        if "." not in callee:
            local = _unique(self.functions_by_file_name.get((call.anchor.file, simple), []))
            target = _select_method(local, call)
            if target is not None:
                return target, "local"

        if callee.startswith(("self.", "cls.", "this.", "$this.")) and callee.count(".") == 1 and caller and caller.class_id:
            methods = _unique(self.methods_by_class_id.get((caller.class_id, simple), []))
            target = _select_method(methods, call)
            if target is not None:
                return target, "instance"

        imported, explicit_import = self._resolve_imported_call(call, callee)
        if imported is not None:
            return imported, "import"
        if explicit_import:
            return None

        injected = self._resolve_injected_receiver(call, callee)
        if injected is not None:
            return injected

        exact = _unique(self.functions_by_exact_key.get(callee, []))
        target = _select_method(exact, call)
        if target is not None:
            return target, "exact"

        if "." not in callee:
            return None
        prefix = callee[: -(len(simple) + 1)]
        suffix = [function for function in self.functions_by_name.get(simple, []) if _module_name(function.anchor.file).endswith(prefix)]
        target = _select_method(_unique(suffix), call)
        return (target, "module_suffix") if target is not None else None

    def _resolve_imported_call(self, call: CallSiteFact, callee: str) -> tuple[FunctionFact | None, bool]:
        parts = callee.split(".")
        alias, simple = parts[0], parts[-1]
        matches: list[FunctionFact] = []
        explicit_import = False
        for item in self.imports_by_file.get(call.anchor.file, []):
            if alias not in item.aliases:
                continue
            if item.kind == "const":
                continue
            explicit_import = True
            exported = item.aliases[alias]
            target_name = simple if len(parts) > 1 or exported in {"*", "default"} else exported
            module_path = item.module.replace("\\", "/")
            module_symbol = _canonical_symbol(item.module)
            direct_keys = [module_symbol]
            if target_name and not module_symbol.endswith(f".{target_name}"):
                direct_keys.insert(0, f"{module_symbol}.{target_name}")
            for key in direct_keys:
                matches.extend(self.functions_by_exact_key.get(key, []))
            if module_path.startswith("."):
                base = posixpath.normpath(posixpath.join(posixpath.dirname(call.anchor.file), module_path))
                candidates = [
                    *self.functions_by_relative_module.get((base, target_name), []),
                    *self.functions_by_relative_module.get((f"{base}/index", target_name), []),
                ]
            else:
                module_tail = _simple_type(module_symbol)
                candidates = self.functions_by_import_tail.get((module_tail, target_name), [])
            matches.extend(function for function in candidates if function.anchor.file != call.anchor.file)
        return _select_method(_unique(matches), call), explicit_import

    def _resolve_injected_receiver(self, call: CallSiteFact, callee: str) -> tuple[FunctionFact, str] | None:
        access = callee.lstrip("$")
        receiver, separator, method = access.rpartition(".")
        if not separator or not receiver or not method:
            return None
        stripped_receiver = receiver.strip()
        ctor_match = re.match(r"^(?:new\s+([A-Za-z_][A-Za-z0-9_$.]*)|([A-Za-z_][A-Za-z0-9_$.]*))\s*\(", stripped_receiver)
        if ctor_match:
            ctor_type = _canonical_symbol(ctor_match.group(1) or ctor_match.group(2))
            if ctor_type and (
                ctor_match.group(1) or ctor_type.rsplit(".", 1)[-1][:1].isupper() or self._methods_for_type(ctor_type, method)
            ):
                ctor_types = list(self._implementations_for_type(ctor_type)) or [ctor_type]
                ctor_matches = [function for type_name in ctor_types for function in self._methods_for_type(type_name, method)]
                target = _select_method(_unique(ctor_matches), call)
                if target is not None:
                    return target, "constructor_receiver"
        # ``this.service.find`` and ``service.find`` describe the same
        # dependency-injected field.  Nested fluent expressions are deliberately
        # ignored; inferring their dynamic result type would be unsound.
        normalized = receiver.removeprefix("this.").removeprefix("self.").rsplit(".", 1)[-1]
        normalized = re.sub(r"[^A-Za-z0-9_$]", "", normalized)
        if not normalized:
            return None
        caller_id = call.enclosing_function_id or ""
        caller = self.functions_by_id.get(caller_id)
        declared_types = self.receiver_types.get((call.anchor.file, caller_id, normalized), ())
        resolution_reason = self.receiver_reasons.get((call.anchor.file, caller_id, normalized), "framework_injection")
        if not declared_types and caller and caller.class_id:
            declared_types = self.class_receiver_types.get((caller.class_id, normalized), ())
            resolution_reason = self.class_receiver_reasons.get((caller.class_id, normalized), "framework_injection")
        if declared_types:
            implementation_types = [
                implementation for declared in declared_types for implementation in self._implementations_for_type(declared)
            ]
            # An explicit interface -> implementation binding is stronger than
            # the interface declaration itself.  If multiple implementations
            # exist, stay unresolved rather than connecting arbitrary code.
            selected_types = implementation_types or list(declared_types)
            matches = [function for type_name in selected_types for function in self._methods_for_type(type_name, method)]
            target = _select_method(_unique(matches), call)
            if target is not None:
                return target, resolution_reason
        class_name = normalized[:1].upper() + normalized[1:]
        target = _select_method(_unique(self.methods_by_class_name.get((class_name, method), [])), call)
        return (target, "receiver_convention") if target is not None else None

    def _implementations_for_type(self, type_name: str) -> tuple[str, ...]:
        canonical = _canonical_symbol(type_name)
        exact = self.implementation_types.get(canonical, ())
        return exact or self.implementation_types.get(_simple_type(canonical), ())

    def _methods_for_type(self, type_name: str, method: str) -> list[FunctionFact]:
        canonical = _canonical_symbol(type_name)
        exact = self.methods_by_class_name.get((canonical, method), [])
        return exact or self.methods_by_class_name.get((_simple_type(canonical), method), [])


def _module_name(file_path: str) -> str:
    parts = file_path.replace("\\", "/").split("/")
    if not parts or not parts[-1].endswith(".py"):
        return ""
    parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(part for part in parts if part)


def _unique(functions: list[FunctionFact]) -> list[FunctionFact]:
    return list({function.id: function for function in functions}.values())


def _select_method(functions: list[FunctionFact], call: CallSiteFact) -> FunctionFact | None:
    """Return a unique method, preferring same-file definitions and using arity to disambiguate."""

    if len(functions) == 1:
        return functions[0]
    if not functions:
        return None
    same_file = [function for function in functions if function.anchor.file == call.anchor.file]
    if len(same_file) == 1:
        return same_file[0]
    pool = same_file if same_file else functions
    argument_count = len(call.argument_sources) + len(call.keyword_sources)
    matching_arity = [
        function
        for function in pool
        if (len(function.params) - (1 if function.class_id and function.params and function.params[0] in {"self", "cls"} else 0))
        == argument_count
    ]
    return matching_arity[0] if len(matching_arity) == 1 else None


def _objects(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def _simple_type(value: str) -> str:
    return _canonical_symbol(value).rsplit(".", 1)[-1].strip()


def _type_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    output: list[str] = []
    for item in value:
        name = _canonical_symbol(_text(item))
        if name and name not in output:
            output.append(name)
    return output


def _canonical_symbol(value: str) -> str:
    normalized = value.strip().replace("->", ".").replace("::", ".").replace("\\", ".")
    return re.sub(r"\.+", ".", normalized).strip(".")


def _type_lookup_keys(value: str) -> list[str]:
    canonical = _canonical_symbol(value)
    return list(dict.fromkeys(item for item in (canonical, _simple_type(canonical)) if item))


def _model_resolution_reason(item: Mapping[str, Any]) -> str:
    explicit = _text(item.get("reason"))
    if explicit:
        return explicit
    if _text(item.get("language")).lower() in {"php", "python"}:
        return "typed_receiver"
    return "framework_injection"
