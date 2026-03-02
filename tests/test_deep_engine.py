"""Tests for DeepEngine — cross-line data flow analysis via taint tracking."""

from __future__ import annotations

from guardianshield.core import GuardianShield
from guardianshield.deep_engine import (
    _JS_SOURCES,
    _PYTHON_SINKS,
    _PYTHON_SOURCES,
    DataFlowChain,
    DeepEngine,
    TaintedVariable,
    TaintKind,
    TaintSink,
    TaintSource,
    _Assignment,
    _build_scope_map_js,
    _build_scope_map_python,
    _compute_confidence,
    _detect_sinks,
    _extract_assignments_js,
    _extract_assignments_python,
    _identify_sources,
    _propagate_taint,
)
from guardianshield.engines import AnalysisEngine
from guardianshield.findings import Finding, FindingType, Severity

# ---------------------------------------------------------------------------
# Fixtures — intentionally vulnerable code samples used to test
# that the deep engine correctly detects cross-line data flow
# vulnerabilities.  These samples contain DELIBERATE security flaws
# (SQL injection, command injection, XSS, etc.) that the scanner
# is designed to catch.
# ---------------------------------------------------------------------------

# Intentionally insecure — taint flows from input() to execute():
PYTHON_SQL_INJECTION = """\
name = input("Enter name: ")
query = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(query)
"""

# Intentionally insecure — Flask request param to SQL:
PYTHON_FLASK_SQL = """\
def get_user(request):
    user_id = request.args.get('id')
    sql = f"SELECT * FROM users WHERE id = {user_id}"
    db.execute(sql)
"""

# Intentionally insecure — multi-hop taint propagation to dangerous eval:
PYTHON_MULTI_HOP = """\
raw = input("data: ")
cleaned = raw.strip()
data = cleaned.upper()
result = eval(data)
"""

# Intentionally insecure — os.system with env var:
PYTHON_CMD_INJECTION = """\
cmd = os.getenv("USER_CMD")
os.system(cmd)
"""

# Intentionally insecure — path traversal:
PYTHON_PATH_TRAVERSAL = """\
filename = request.args.get('file')
open(filename)
"""

# Intentionally insecure — XSS via render_template_string:
PYTHON_XSS = """\
def render(request):
    content = request.form.get('content')
    return render_template_string(content)
"""

# Clean code — no taint sources, should produce no findings:
PYTHON_CLEAN = """\
x = 1 + 2
y = x * 3
print(y)
"""

# Intentionally insecure — tests scope isolation (should NOT fire):
PYTHON_SCOPE_ISOLATION = """\
def func_a():
    secret = input("secret: ")

def func_b():
    cursor.execute(secret)
"""

# Intentionally insecure — module-scope taint accessible in function:
PYTHON_MODULE_SCOPE = """\
config = os.environ.get("DB_URL")

def connect():
    db.execute(config)
"""

# Intentionally insecure — json.loads as external data source to eval:
PYTHON_JSON_FLOW = """\
data = json.loads(payload)
result = eval(data)
"""

# Intentionally insecure — JS: req.params to db.query:
JS_SQL_INJECTION = """\
function getUser(req, res) {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query);
}
"""

# Intentionally insecure — JS: process.env to dangerous eval:
JS_CMD_INJECTION = """\
const config = process.env.DYNAMIC_CODE;
eval(config);
"""

# Intentionally insecure — JS: req.body to innerHTML:
JS_XSS = """\
function render(req, res) {
    const content = req.body.html;
    element.innerHTML = content;
}
"""

# Clean JS code — no data flow issues:
JS_CLEAN = """\
const x = 1 + 2;
const y = x * 3;
console.log(y);
"""

# Intentionally insecure — JS: req.query to res.send:
JS_RESPONSE_XSS = """\
function handler(req, res) {
    const name = req.query.name;
    res.send(name);
}
"""


# ---------------------------------------------------------------------------
# TestTaintSourceIdentification
# ---------------------------------------------------------------------------


class TestTaintSourceIdentification:
    def test_python_input_detected(self):
        code = 'user_input = input("Enter: ")'
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].name == "user_input"
        assert tainted[0].source.kind == TaintKind.USER_INPUT

    def test_flask_request_args_detected(self):
        code = "name = request.args.get('name')"
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].source.kind == TaintKind.REQUEST_PARAM

    def test_django_request_get_detected(self):
        code = "val = request.GET.get('key')"
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].source.kind == TaintKind.REQUEST_PARAM

    def test_os_environ_detected(self):
        code = 'key = os.environ["SECRET"]'
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].source.kind == TaintKind.ENV_VAR

    def test_json_loads_detected(self):
        code = "data = json.loads(payload)"
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].source.kind == TaintKind.EXTERNAL_DATA

    def test_non_taint_not_detected(self):
        code = "x = 1 + 2"
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert tainted == []

    def test_scope_tracking_in_function(self):
        code = "def foo():\n    name = input('name: ')"
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].scope == "foo"

    def test_js_req_params_detected(self):
        lines = ["const id = req.params.id;"]
        assigns = _extract_assignments_js(lines)
        tainted = _identify_sources(assigns, _JS_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].source.kind == TaintKind.REQUEST_PARAM

    def test_js_process_env_detected(self):
        lines = ["const key = process.env.SECRET;"]
        assigns = _extract_assignments_js(lines)
        tainted = _identify_sources(assigns, _JS_SOURCES)
        assert len(tainted) == 1
        assert tainted[0].source.kind == TaintKind.ENV_VAR

    def test_multiple_sources_in_one_file(self):
        code = "a = input('x')\nb = request.args.get('y')\nc = 42"
        lines = code.splitlines()
        assigns = _extract_assignments_python(code, lines)
        tainted = _identify_sources(assigns, _PYTHON_SOURCES)
        assert len(tainted) == 2
        names = {t.name for t in tainted}
        assert names == {"a", "b"}


# ---------------------------------------------------------------------------
# TestTaintPropagation
# ---------------------------------------------------------------------------


class TestTaintPropagation:
    def _make_tainted(self, name, scope="__module__", line=1):
        src = TaintSource(
            name, TaintKind.USER_INPUT, line, f"{name} = input()", scope,
        )
        return TaintedVariable(name, src, line, [name], scope)

    def test_simple_reassignment(self):
        assigns = [
            _Assignment("x", "x = input()", 1, "__module__"),
            _Assignment("y", "y = x", 2, "__module__"),
        ]
        tainted = [self._make_tainted("x")]
        result = _propagate_taint(assigns, tainted)
        names = {t.name for t in result}
        assert "y" in names

    def test_string_concatenation(self):
        assigns = [
            _Assignment("name", "name = input()", 1, "__module__"),
            _Assignment("query", 'query = "SELECT " + name', 2, "__module__"),
        ]
        tainted = [self._make_tainted("name")]
        result = _propagate_taint(assigns, tainted)
        names = {t.name for t in result}
        assert "query" in names

    def test_multi_hop(self):
        assigns = [
            _Assignment("a", "a = input()", 1, "__module__"),
            _Assignment("b", "b = a.strip()", 2, "__module__"),
            _Assignment("c", "c = b.upper()", 3, "__module__"),
        ]
        tainted = [self._make_tainted("a")]
        result = _propagate_taint(assigns, tainted)
        names = {t.name for t in result}
        assert names == {"a", "b", "c"}
        # Check propagation chain
        c_var = next(t for t in result if t.name == "c")
        assert c_var.propagation_chain == ["a", "b", "c"]

    def test_scope_isolation(self):
        assigns = [
            _Assignment("x", "x = input()", 1, "func_a"),
            _Assignment("y", "y = x", 2, "func_b"),
        ]
        tainted = [self._make_tainted("x", scope="func_a")]
        result = _propagate_taint(assigns, tainted)
        names = {t.name for t in result}
        assert "y" not in names  # different scope, no propagation

    def test_module_scope_accessible_in_function(self):
        assigns = [
            _Assignment("x", "x = input()", 1, "__module__"),
            _Assignment("y", "y = x", 2, "my_func"),
        ]
        tainted = [self._make_tainted("x", scope="__module__")]
        result = _propagate_taint(assigns, tainted)
        names = {t.name for t in result}
        assert "y" in names  # module scope accessible everywhere

    def test_fstring_propagation(self):
        assigns = [
            _Assignment("name", "name = input()", 1, "__module__"),
            _Assignment("msg", 'msg = f"Hello {name}"', 2, "__module__"),
        ]
        tainted = [self._make_tainted("name")]
        result = _propagate_taint(assigns, tainted)
        names = {t.name for t in result}
        assert "msg" in names

    def test_max_passes_limit(self):
        # Chain of 10 hops — should stop after max_passes=5
        assigns = [_Assignment("v0", "v0 = input()", 1, "__module__")]
        for i in range(1, 10):
            assigns.append(
                _Assignment(f"v{i}", f"v{i} = v{i - 1}", i + 1, "__module__"),
            )
        tainted = [self._make_tainted("v0")]
        result = _propagate_taint(assigns, tainted, max_passes=5)
        names = {t.name for t in result}
        # v0 through v5 should be tainted (original + 5 passes)
        assert "v0" in names
        assert "v5" in names

    def test_no_propagation_clean(self):
        assigns = [
            _Assignment("x", "x = 42", 1, "__module__"),
            _Assignment("y", "y = x", 2, "__module__"),
        ]
        result = _propagate_taint(assigns, [])
        assert result == []


# ---------------------------------------------------------------------------
# TestSinkDetection
# ---------------------------------------------------------------------------


class TestSinkDetection:
    def _make_tv(
        self, name, kind=TaintKind.USER_INPUT, scope="__module__", line=1,
    ):
        src = TaintSource(
            name, kind, line, f"{name} = input()", scope,
        )
        return TaintedVariable(name, src, line, [name], scope)

    def test_sql_injection_sink(self):
        lines = ["cursor.execute(query)"]
        scope_map = {1: "__module__"}
        tainted = [self._make_tv("query")]
        chains = _detect_sinks(lines, _PYTHON_SINKS, tainted, scope_map)
        assert len(chains) == 1
        assert chains[0].sink.finding_type == FindingType.SQL_INJECTION

    def test_command_injection_sink(self):
        lines = ["os.system(cmd)"]
        scope_map = {1: "__module__"}
        tainted = [self._make_tv("cmd")]
        chains = _detect_sinks(lines, _PYTHON_SINKS, tainted, scope_map)
        assert len(chains) == 1
        assert chains[0].sink.finding_type == FindingType.COMMAND_INJECTION

    def test_eval_sink(self):
        # Intentionally insecure — tests that eval() with tainted arg
        # is flagged as command injection
        lines = ["result = eval(data)"]
        scope_map = {1: "__module__"}
        tainted = [self._make_tv("data")]
        chains = _detect_sinks(lines, _PYTHON_SINKS, tainted, scope_map)
        assert len(chains) == 1
        assert chains[0].sink.finding_type == FindingType.COMMAND_INJECTION

    def test_path_traversal_sink(self):
        lines = ["open(filename)"]
        scope_map = {1: "__module__"}
        tainted = [self._make_tv("filename")]
        chains = _detect_sinks(lines, _PYTHON_SINKS, tainted, scope_map)
        assert len(chains) == 1
        assert chains[0].sink.finding_type == FindingType.PATH_TRAVERSAL

    def test_clean_sink_no_finding(self):
        lines = ["cursor.execute(safe_query)"]
        scope_map = {1: "__module__"}
        tainted = [self._make_tv("tainted_var")]
        chains = _detect_sinks(lines, _PYTHON_SINKS, tainted, scope_map)
        assert chains == []

    def test_multiple_sinks(self):
        lines = ["cursor.execute(query)", "os.system(cmd)"]
        scope_map = {1: "__module__", 2: "__module__"}
        tainted = [self._make_tv("query"), self._make_tv("cmd")]
        chains = _detect_sinks(lines, _PYTHON_SINKS, tainted, scope_map)
        assert len(chains) == 2

    def test_comment_line_skipped(self):
        lines = ["# cursor.execute(query)"]
        scope_map = {1: "__module__"}
        tainted = [self._make_tv("query")]
        chains = _detect_sinks(lines, _PYTHON_SINKS, tainted, scope_map)
        assert chains == []


# ---------------------------------------------------------------------------
# TestEndToEndPythonFlows
# ---------------------------------------------------------------------------


class TestEndToEndPythonFlows:
    def test_input_to_sql(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_SQL_INJECTION, language="python")
        assert len(findings) >= 1
        sql = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sql) >= 1
        assert sql[0].details.get("engine") == "deep"

    def test_flask_request_to_sql(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_FLASK_SQL, language="python")
        sql = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sql) >= 1

    def test_multi_hop_to_eval(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_MULTI_HOP, language="python")
        cmd = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmd) >= 1
        # Check propagation chain in details
        chain = cmd[0].details.get("propagation_chain", [])
        assert len(chain) >= 2

    def test_env_var_to_os_system(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_CMD_INJECTION, language="python")
        cmd = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmd) >= 1
        assert cmd[0].details.get("taint_kind") == "env_var"

    def test_request_to_path_traversal(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_PATH_TRAVERSAL, language="python")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1

    def test_clean_code_no_findings(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_CLEAN, language="python")
        assert findings == []

    def test_module_scope_to_function_sink(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_MODULE_SCOPE, language="python")
        assert len(findings) >= 1

    def test_xss_template_injection(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_XSS, language="python")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1

    def test_json_to_eval(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_JSON_FLOW, language="python")
        assert len(findings) >= 1
        assert findings[0].details.get("taint_kind") == "external_data"


# ---------------------------------------------------------------------------
# TestEndToEndJSFlows
# ---------------------------------------------------------------------------


class TestEndToEndJSFlows:
    def test_req_params_to_db_query(self):
        engine = DeepEngine()
        findings = engine.analyze(JS_SQL_INJECTION, language="javascript")
        sql = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sql) >= 1
        assert sql[0].details.get("engine") == "deep"

    def test_process_env_to_eval(self):
        engine = DeepEngine()
        findings = engine.analyze(JS_CMD_INJECTION, language="javascript")
        cmd = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmd) >= 1

    def test_req_body_to_innerhtml(self):
        engine = DeepEngine()
        findings = engine.analyze(JS_XSS, language="javascript")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1

    def test_clean_js_no_findings(self):
        engine = DeepEngine()
        findings = engine.analyze(JS_CLEAN, language="javascript")
        assert findings == []

    def test_req_query_to_res_send(self):
        engine = DeepEngine()
        findings = engine.analyze(JS_RESPONSE_XSS, language="javascript")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1


# ---------------------------------------------------------------------------
# TestDeepEngineProtocol
# ---------------------------------------------------------------------------


class TestDeepEngineProtocol:
    def test_implements_analysis_engine(self):
        engine = DeepEngine()
        assert isinstance(engine, AnalysisEngine)

    def test_name_is_deep(self):
        engine = DeepEngine()
        assert engine.name == "deep"

    def test_capabilities_keys(self):
        engine = DeepEngine()
        caps = engine.capabilities()
        assert "description" in caps
        assert "analysis_type" in caps
        assert "supported_languages" in caps
        assert "speed" in caps

    def test_capabilities_data_flow_true(self):
        engine = DeepEngine()
        caps = engine.capabilities()
        assert caps["cross_line"] is True
        assert caps["data_flow"] is True
        assert caps["semantic"] is False

    def test_analyze_returns_findings_for_vulnerable_code(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_SQL_INJECTION, language="python")
        assert len(findings) > 0
        assert all(isinstance(f, Finding) for f in findings)

    def test_analyze_returns_empty_for_clean_code(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_CLEAN, language="python")
        assert findings == []

    def test_unsupported_language_returns_empty(self):
        engine = DeepEngine()
        findings = engine.analyze("some code", language="rust")
        assert findings == []

    def test_language_from_file_path(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_SQL_INJECTION, file_path="app.py")
        assert len(findings) > 0

    def test_findings_tagged_with_engine(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_SQL_INJECTION, language="python")
        for f in findings:
            assert f.details.get("engine") == "deep"
            assert f.scanner == "deep_engine"

    def test_sensitivity_filtering(self):
        engine = DeepEngine()
        high = engine.analyze(
            PYTHON_SQL_INJECTION, language="python", sensitivity="high",
        )
        low = engine.analyze(
            PYTHON_SQL_INJECTION, language="python", sensitivity="low",
        )
        assert len(high) >= len(low)


# ---------------------------------------------------------------------------
# TestDeepEngineCoreIntegration
# ---------------------------------------------------------------------------


class TestDeepEngineCoreIntegration:
    def test_deep_engine_registered(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        names = shield.engine_registry.available_names
        assert "deep" in names

    def test_list_engines_shows_deep(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        engines = shield.list_engines()
        names = {e["name"] for e in engines}
        assert "deep" in names
        deep_entry = next(e for e in engines if e["name"] == "deep")
        # Deep is registered but NOT enabled by default
        assert deep_entry["enabled"] is False

    def test_set_engines_deep_only(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        result = shield.set_engines(["deep"])
        assert result == ["deep"]

    def test_scan_code_with_deep_engine(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        findings = shield.scan_code(
            PYTHON_SQL_INJECTION, language="python", engines=["deep"],
        )
        deep = [f for f in findings if f.details.get("engine") == "deep"]
        assert len(deep) >= 1

    def test_scan_code_both_engines(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        findings = shield.scan_code(
            PYTHON_SQL_INJECTION, language="python",
            engines=["regex", "deep"],
        )
        engines_used = {
            f.details.get("engine")
            for f in findings
            if "engine" in f.details
        }
        assert "deep" in engines_used

    def test_status_shows_deep_engine(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        status = shield.status()
        engine_names = {e["name"] for e in status["engines"]}
        assert "deep" in engine_names


# ---------------------------------------------------------------------------
# TestConfidenceScoring
# ---------------------------------------------------------------------------


class TestConfidenceScoring:
    def _make_chain(self, kind, chain_len=1):
        src = TaintSource("v", kind, 1, "v = source()", "__module__")
        sink = TaintSink(
            "execute", FindingType.SQL_INJECTION, Severity.CRITICAL,
            ["CWE-89"], 5, "v", "__module__",
        )
        chain = ["v"] + [f"v{i}" for i in range(1, chain_len)]
        tv = TaintedVariable("v", src, 1, chain, "__module__")
        return DataFlowChain(src, sink, [tv], 0.0)

    def test_request_param_highest(self):
        chain = self._make_chain(TaintKind.REQUEST_PARAM)
        conf = _compute_confidence(chain)
        assert conf == 0.90

    def test_env_var_lowest(self):
        chain = self._make_chain(TaintKind.ENV_VAR)
        conf = _compute_confidence(chain)
        assert conf == 0.70

    def test_longer_chain_lower_confidence(self):
        short = self._make_chain(TaintKind.USER_INPUT, chain_len=1)
        long_ = self._make_chain(TaintKind.USER_INPUT, chain_len=5)
        assert _compute_confidence(short) > _compute_confidence(long_)

    def test_confidence_within_bounds(self):
        for kind in TaintKind:
            for length in (1, 3, 10):
                chain = self._make_chain(kind, chain_len=length)
                conf = _compute_confidence(chain)
                assert 0.70 <= conf <= 0.90


# ---------------------------------------------------------------------------
# TestDataFlowChain
# ---------------------------------------------------------------------------


class TestDataFlowChain:
    def test_evidence_string(self):
        src = TaintSource(
            "name", TaintKind.REQUEST_PARAM, 1,
            "name = request.args.get('name')", "__module__",
        )
        sink = TaintSink(
            "cursor.execute", FindingType.SQL_INJECTION,
            Severity.CRITICAL, ["CWE-89"], 3, "query", "__module__",
        )
        tv = TaintedVariable("query", src, 2, ["name", "query"], "__module__")
        chain = DataFlowChain(src, sink, [tv], 0.85)
        evidence = chain.evidence_string()
        assert "name -> query" in evidence
        assert "request_param" in evidence
        assert "cursor.execute" in evidence


# ---------------------------------------------------------------------------
# TestScopeTracking
# ---------------------------------------------------------------------------


class TestScopeTracking:
    def test_python_scope_map(self):
        code = "x = 1\ndef foo():\n    y = 2\nz = 3"
        scope_map = _build_scope_map_python(code, 4)
        assert scope_map[1] == "__module__"
        assert scope_map[3] == "foo"
        assert scope_map[4] == "__module__"

    def test_js_scope_map(self):
        lines = [
            "const x = 1;",
            "function handler(req) {",
            "    const y = req.params.id;",
            "}",
            "const z = 2;",
        ]
        scope_map = _build_scope_map_js(lines)
        assert scope_map[1] == "__module__"
        assert scope_map[3] == "handler"
        assert scope_map[5] == "__module__"

    def test_scope_isolation_prevents_false_positive(self):
        engine = DeepEngine()
        findings = engine.analyze(PYTHON_SCOPE_ISOLATION, language="python")
        # secret is in func_a scope, sink is in func_b scope — no flow
        assert findings == []


# ---------------------------------------------------------------------------
# TestPerformance
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_empty_code_fast(self):
        engine = DeepEngine()
        findings = engine.analyze("", language="python")
        assert findings == []

    def test_no_sources_early_exit(self):
        code = "\n".join(f"x{i} = {i}" for i in range(100))
        engine = DeepEngine()
        findings = engine.analyze(code, language="python")
        assert findings == []

    def test_large_file_completes(self):
        # Generate a file with one taint source and many clean lines
        lines = ['name = input("x")']
        lines.extend(f"v{i} = {i}" for i in range(500))
        lines.append("cursor.execute(name)")
        code = "\n".join(lines)
        engine = DeepEngine()
        findings = engine.analyze(code, language="python")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# TestASTFallback
# ---------------------------------------------------------------------------


class TestASTFallback:
    def test_syntax_error_falls_back_to_regex(self):
        # Invalid Python syntax — should fall back to regex extraction
        code = "x = input('y')\n::: invalid syntax\ncursor.execute(x)"
        engine = DeepEngine()
        # Should not raise — may or may not find the flow depending on
        # regex extraction success
        findings = engine.analyze(code, language="python")
        # No crash is the main assertion
        assert isinstance(findings, list)
