from __future__ import annotations

import json

from auditforge.analysis.call_resolution import CallResolver, resolution_models_from_diagnostics
from auditforge.analysis.candidates import build_trace_candidates
from auditforge.analysis.graph import build_graph
from auditforge.analysis.scanner import extract_imports, index_source_files, scan_repo


def test_composer_promoted_properties_resolve_controller_service_repository_chain(tmp_path) -> None:
    _write_composer(tmp_path, {"App\\": "src/"})
    _write(
        tmp_path / "src/Controller/SearchController.php",
        r"""<?php
namespace App\Controller;
use App\Service\SearchService;

class SearchController {
    public function __construct(private SearchService $service) {}

    public function search($request) {
        $term = $request->query('q');
        return $this->service->search($term);
    }
}
""",
    )
    _write(
        tmp_path / "src/Service/SearchService.php",
        r"""<?php
namespace App\Service;
use App\Repository\UserRepository as Repo;

class SearchService {
    public function __construct(private Repo $repository) {}

    public function search($term) {
        return $this->repository->find($term);
    }
}
""",
    )
    _write(
        tmp_path / "src/Repository/UserRepository.php",
        r"""<?php
namespace App\Repository;

class UserRepository {
    public function find($term) {
        $sql = "SELECT * FROM users WHERE name = '$term'";
        return DB::raw($sql);
    }
}
""",
    )

    facts = scan_repo(tmp_path)
    graph = build_graph(facts)
    candidates = build_trace_candidates(facts, graph)

    assert facts.analysis_diagnostics["php_symbols"]["composer"]["matched_classes"] == 3
    typed_edges = [edge for edge in graph.edges if edge.metadata.get("resolution_reason") == "typed_receiver"]
    assert len(typed_edges) >= 2
    assert not any(edge.from_id == edge.to_id and edge.kind == "CALLS" for edge in graph.edges)
    candidate = next(item for item in candidates if item.sink.file.endswith("UserRepository.php"))
    assert candidate.source.file.endswith("SearchController.php")
    assert candidate.vuln_class == "injection"


def test_php_typed_parameters_and_constructor_assignment_create_receiver_models(tmp_path) -> None:
    _write_composer(tmp_path, {"App\\": ["src/"]})
    _write(
        tmp_path / "src/Repository/UserRepository.php",
        r"""<?php
namespace App\Repository;
class UserRepository { public function find($value) { return $value; } }
""",
    )
    _write(
        tmp_path / "src/Service/UserService.php",
        r"""<?php
namespace App\Service;
use App\Repository\UserRepository;

class UserService {
    private UserRepository $repository;

    public function __construct(UserRepository $repository) {
        $this->repository = $repository;
    }

    public function direct(UserRepository $local, $value) {
        $fresh = new UserRepository();
        $local->find($value);
        return $fresh->find($value);
    }
}
""",
    )

    facts = scan_repo(tmp_path)
    models = facts.analysis_diagnostics["php_symbols"]
    receivers = {(item["receiver"], item["binding_kind"]): item["types"] for item in models["receiver_types"]}
    class_receivers = {name: types for item in models["class_receiver_types"] for name, types in item["receivers"].items()}

    assert receivers[("local", "parameter_type")] == [r"App\Repository\UserRepository"]
    assert receivers[("fresh", "local_new")] == [r"App\Repository\UserRepository"]
    assert class_receivers["repository"] == [r"App\Repository\UserRepository"]


def test_php_fqcn_resolution_does_not_cross_same_named_namespaces(tmp_path) -> None:
    _write_composer(tmp_path, {"App\\": "src/"})
    _write(
        tmp_path / "src/One/Repository.php",
        r"""<?php
namespace App\One;
class Repository { public function load($value) { return $value; } }
""",
    )
    _write(
        tmp_path / "src/Two/Repository.php",
        r"""<?php
namespace App\Two;
class Repository { public function load($value) { return $value; } }
""",
    )
    _write(
        tmp_path / "src/Service.php",
        r"""<?php
namespace App;
use App\One\Repository as Repo;
class Service {
    public function run(Repo $repository, $value) {
        return $repository->load($value);
    }
}
""",
    )

    facts = scan_repo(tmp_path)
    resolver = CallResolver(facts.functions, facts.imports, resolution_models_from_diagnostics(facts.analysis_diagnostics))
    call = next(item for item in facts.call_sites if item.callee == "$repository->load")
    resolved = resolver.resolve_with_reason(call)

    assert resolved is not None
    assert resolved[0].anchor.file == "src/One/Repository.php"
    assert resolved[1] == "typed_receiver"


def test_grouped_php_imports_and_trait_uses_are_distinguished(tmp_path) -> None:
    path = tmp_path / "src/Example.php"
    _write(
        path,
        r"""<?php
namespace App;
use Vendor\Package\{Client, Request as HttpRequest};
use function Vendor\Helpers\{clean, encode as encode_value};

class Example {
    use TracksChanges;
}
""",
    )
    source_file = next(item for item in index_source_files(tmp_path) if item.file.path.endswith("Example.php"))
    imports = extract_imports(source_file)

    assert {(item.module, item.kind) for item in imports} == {
        (r"Vendor\Package\Client", "class"),
        (r"Vendor\Package\Request", "class"),
        (r"Vendor\Helpers\clean", "function"),
        (r"Vendor\Helpers\encode", "function"),
    }
    assert not any("TracksChanges" in item.module for item in imports)


def test_composer_diagnostics_reject_paths_outside_repository(tmp_path) -> None:
    _write(
        tmp_path / "composer.json",
        json.dumps(
            {
                "autoload": {"psr-4": {"App\\": "src/", "Escape\\": "../outside"}},
                "autoload-dev": {"psr-4": {"Tests\\": ["tests/", "spec/"]}},
            }
        ),
    )
    _write(tmp_path / "src/App.php", "<?php namespace App; class App {}\n")

    facts = scan_repo(tmp_path)
    composer = facts.analysis_diagnostics["php_symbols"]["composer"]

    assert any(item["dev"] and item["prefix"] == "Tests\\" for item in composer["psr4"])
    assert any(item["reason"] == "autoload path escapes repository" for item in composer["invalid_entries"])


def test_laravel_container_binding_selects_explicit_interface_implementation(tmp_path) -> None:
    _write_composer(tmp_path, {"App\\": "src/"})
    _write(
        tmp_path / "src/Contracts/Search.php",
        r"""<?php
namespace App\Contracts;
interface Search { public function execute($value); }
""",
    )
    _write(
        tmp_path / "src/Search/DatabaseSearch.php",
        r"""<?php
namespace App\Search;
use App\Contracts\Search;
class DatabaseSearch implements Search { public function execute($value) { return $value; } }
""",
    )
    _write(
        tmp_path / "src/Search/RemoteSearch.php",
        r"""<?php
namespace App\Search;
use App\Contracts\Search;
class RemoteSearch implements Search { public function execute($value) { return $value; } }
""",
    )
    _write(
        tmp_path / "src/Providers/AppServiceProvider.php",
        r"""<?php
namespace App\Providers;
use App\Contracts\Search;
use App\Search\DatabaseSearch;
class AppServiceProvider {
    public function register() {
        $this->app->bind(Search::class, DatabaseSearch::class);
    }
}
""",
    )
    _write(
        tmp_path / "src/Controller.php",
        r"""<?php
namespace App;
use App\Contracts\Search;
class Controller {
    public function __construct(private Search $search) {}
    public function run($value) { return $this->search->execute($value); }
}
""",
    )

    facts = scan_repo(tmp_path)
    resolver = CallResolver(facts.functions, facts.imports, resolution_models_from_diagnostics(facts.analysis_diagnostics))
    call = next(item for item in facts.call_sites if item.callee == "$this->search->execute")
    resolved = resolver.resolve_with_reason(call)

    assert resolved is not None
    assert resolved[0].anchor.file == "src/Search/DatabaseSearch.php"
    assert facts.analysis_diagnostics["php_symbols"]["container_bindings"] == [
        {"interface": r"App\Contracts\Search", "implementations": [r"App\Search\DatabaseSearch"]}
    ]


def _write_composer(root, psr4) -> None:  # noqa: ANN001
    _write(root / "composer.json", json.dumps({"autoload": {"psr-4": psr4}}))


def _write(path, content: str) -> None:  # noqa: ANN001
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
