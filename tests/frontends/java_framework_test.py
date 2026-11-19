from __future__ import annotations

from auditforge.analysis.candidates import build_trace_candidates
from auditforge.analysis.graph import build_graph
from auditforge.analysis.scanner import scan_repo


def test_spring_injection_reaches_mybatis_dynamic_sql(tmp_path) -> None:
    _write(
        tmp_path / "src/main/java/demo/SearchController.java",
        """package demo;
@RestController
public class SearchController {
    private final SearchService gateway;
    @GetMapping("/search")
    public String search(@RequestParam String q) {
        return gateway.search(q);
    }
}
""",
    )
    _write(
        tmp_path / "src/main/java/demo/SearchService.java",
        """package demo;
public interface SearchService {
    String search(String query);
}
""",
    )
    _write(
        tmp_path / "src/main/java/demo/SearchServiceImpl.java",
        """package demo;
@Service
public class SearchServiceImpl implements SearchService {
    private final SearchMapper queryPort;
    public String search(String query) {
        return queryPort.findByName(query);
    }
}
""",
    )
    _write(
        tmp_path / "src/main/java/demo/SearchMapper.java",
        """package demo;
@Mapper
public interface SearchMapper {
    String findByName(@Param("needle") String query);
}
""",
    )
    _write(
        tmp_path / "src/main/resources/mapper/SearchMapper.xml",
        """<?xml version="1.0" encoding="UTF-8" ?>
<mapper namespace="demo.SearchMapper">
  <select id="findByName" resultType="String">
    SELECT name FROM users WHERE name LIKE '%${needle}%'
  </select>
</mapper>
""",
    )

    facts = scan_repo(tmp_path)
    graph = build_graph(facts)
    candidates = build_trace_candidates(facts, graph)

    mybatis_sinks = [item for item in facts.sinks if item.anchor.file.endswith("SearchMapper.xml")]
    assert len(mybatis_sinks) == 1
    assert mybatis_sinks[0].variables == ["query"]
    candidate = next(item for item in candidates if item.sink.file.endswith("SearchMapper.xml"))
    assert candidate.source.file.endswith("SearchController.java")
    assert candidate.source.symbol == "q"
    assert candidate.sink.symbol == "demo.SearchMapper.findByName"
    assert any(step.kind == "framework_binding" for step in candidate.steps)
    assert any(edge.metadata.get("resolution_reason") == "framework_injection" for edge in graph.edges)


def test_mybatis_bound_parameter_is_not_reported_as_dynamic_sql(tmp_path) -> None:
    _write(
        tmp_path / "src/main/java/demo/SafeMapper.java",
        """package demo;
public interface SafeMapper {
    String findByName(String query);
}
""",
    )
    _write(
        tmp_path / "src/main/resources/mapper/SafeMapper.xml",
        """<mapper namespace="demo.SafeMapper">
  <select id="findByName">SELECT name FROM users WHERE name = #{query}</select>
</mapper>
""",
    )

    facts = scan_repo(tmp_path)

    assert not [item for item in facts.sinks if item.anchor.file.endswith("SafeMapper.xml")]
    assert facts.analysis_diagnostics["java_framework"]["mybatis"]["ignored_bound_parameters"] == "#{...}"


def test_mybatis_annotation_dynamic_sql_uses_param_alias(tmp_path) -> None:
    _write(
        tmp_path / "src/main/java/demo/AnnotatedMapper.java",
        """package demo;
public interface AnnotatedMapper {
    @Select("SELECT ${column} FROM users WHERE name = #{query}")
    String find(@Param("column") String selectedColumn, @Param("query") String name);
}
""",
    )

    facts = scan_repo(tmp_path)
    annotation_sinks = [item for item in facts.sinks if item.expression.startswith("MyBatis @Select")]

    assert len(annotation_sinks) == 1
    assert annotation_sinks[0].variables == ["selectedColumn"]
    assert facts.analysis_diagnostics["java_framework"]["mybatis"]["annotation_dynamic_sql_sinks"] == 1


def test_mybatis_statement_includes_dynamic_fragment_and_single_parameter_property(tmp_path) -> None:
    _write(
        tmp_path / "src/main/java/demo/ExampleMapper.java",
        """package demo;
public interface ExampleMapper {
    String selectByExample(Example example);
}
""",
    )
    _write(
        tmp_path / "src/main/resources/mapper/ExampleMapper.xml",
        """<mapper namespace="demo.ExampleMapper">
  <sql id="Order_Clause">ORDER BY ${orderByClause}</sql>
  <sql id="Example_Where_Clause"><foreach collection="criteria" item="criterion"><when test="criterion.noValue">AND ${criterion.condition}</when></foreach></sql>
  <select id="selectByExample">SELECT * FROM users <include refid="Order_Clause" /><include refid="Example_Where_Clause" /></select>
</mapper>
""",
    )

    facts = scan_repo(tmp_path)
    xml_sinks = [item for item in facts.sinks if item.anchor.file.endswith("ExampleMapper.xml")]

    assert len(xml_sinks) == 1
    assert xml_sinks[0].anchor.symbol == "demo.ExampleMapper.selectByExample"
    assert xml_sinks[0].variables == ["example.orderByClause"]


def test_request_body_object_reaches_mybatis_dynamic_property(tmp_path) -> None:
    _write(
        tmp_path / "src/main/java/demo/ExampleController.java",
        """package demo;
@RestController
public class ExampleController {
    private ExampleMapper mapper;
    @PostMapping("/search")
    public String search(@RequestBody Example example) {
        return mapper.selectByExample(example);
    }
}
""",
    )
    _write(
        tmp_path / "src/main/java/demo/ExampleMapper.java",
        """package demo;
public interface ExampleMapper {
    String selectByExample(Example example);
}
""",
    )
    _write(
        tmp_path / "src/main/resources/mapper/ExampleMapper.xml",
        """<mapper namespace="demo.ExampleMapper">
  <select id="selectByExample">SELECT * FROM users ORDER BY ${orderByClause}</select>
</mapper>
""",
    )

    facts = scan_repo(tmp_path)
    candidates = build_trace_candidates(facts, build_graph(facts))

    candidate = next(item for item in candidates if item.sink.file.endswith("ExampleMapper.xml"))
    assert candidate.source.symbol == "example"
    assert candidate.sink.symbol == "demo.ExampleMapper.selectByExample"


def _write(path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
