"""Scan-history UI: the data it depends on (history.py) and its pure logic.

Python tests cover the additive read fields + the fingerprint cache. The JS
logic that decides what the UI *claims* (is a 0-finding run clean? is this
delta a regression or just a baseline? is every dynamic string escaped?) is
exercised through `tests/js/dashboard_runner.js` in a bare node vm context —
skipped when node isn't installed, so the suite stays runnable without it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from janus.core.model import Finding
from janus.dashboard import history
from janus.dashboard.server import build_app

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "js" / "dashboard_runner.js"
STATIC = ROOT / "janus" / "dashboard" / "static"
NODE = shutil.which("node")


def _finding(title: str, path: str = "a.py", line: int = 1) -> Finding:
    return Finding(title=title, severity="high", category="other", engine="code",
                   tool="builtin", path=path, line=line)


def _record(tmp_path, run_id, command, findings, *, tool_results=()):
    history.record_scan(tmp_path, run_id=run_id, command=command,
                        scope_manifest={"engagement": "eng"}, findings=findings,
                        tool_results=tool_results)


# --------------------------------------------------------------------------
# history.py: additive fields + cache
# --------------------------------------------------------------------------

def test_list_rows_carry_kind_previous_run_and_baseline(tmp_path):
    a, b = _finding("a"), _finding("b", "b.py")
    _record(tmp_path, "code1", "scan code", [a])
    _record(tmp_path, "recon1", "scan recon --mode passive", [b])
    _record(tmp_path, "code2", "scan code", [a, b])
    rows = {r["run_id"]: r for r in history.list_scans(tmp_path)}

    assert rows["code1"]["baseline"] is True and rows["code1"]["previous_run_id"] is None
    assert rows["recon1"]["baseline"] is True, "a recon run must not be compared with a code run"
    assert rows["code2"]["baseline"] is False and rows["code2"]["previous_run_id"] == "code1"
    assert rows["code2"]["kind"] == "scan code" and rows["recon1"]["kind"] == "scan recon"
    # the pre-existing delta contract is untouched
    assert rows["code2"]["delta"] == {"new": 1, "fixed": 0, "same": 1}


def test_load_scan_exposes_comparison_target(tmp_path):
    a = _finding("a")
    _record(tmp_path, "r1", "scan code", [a])
    _record(tmp_path, "r2", "scan code", [])
    scan = history.load_scan(tmp_path, "r2")
    assert scan["previous_run_id"] == "r1" and scan["baseline"] is False and scan["kind"] == "scan code"
    assert scan["delta"] == {"new": 0, "fixed": 1, "same": 0}
    first = history.load_scan(tmp_path, "r1")
    assert first["baseline"] is True and first["previous_run_id"] is None


def test_fingerprint_cache_avoids_rereading_unchanged_runs(tmp_path, monkeypatch):
    _record(tmp_path, "r1", "scan code", [_finding("a")])
    _record(tmp_path, "r2", "scan code", [_finding("a"), _finding("b", "b.py")])
    history._FP_CACHE.clear()
    history.list_scans(tmp_path)                     # warm

    reads = []
    real = Path.read_text

    def counting(self, *a, **k):
        if self.name == "findings.json":
            reads.append(str(self))
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", counting)
    history.list_scans(tmp_path)
    assert reads == [], "unchanged runs must be served from the cache, not re-parsed on every list call"


def test_fingerprint_cache_is_invalidated_when_a_record_is_rewritten(tmp_path):
    _record(tmp_path, "r1", "scan code", [_finding("a")])
    _record(tmp_path, "r2", "scan code", [_finding("a")])
    assert history.list_scans(tmp_path)[0]["delta"]["new"] == 0

    p = tmp_path / "scans" / "r2" / "findings.json"
    rows = json.loads(p.read_text(encoding="utf-8"))
    rows.append(_finding("late", "late.py").to_dict())
    p.write_text(json.dumps(rows), encoding="utf-8")
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))

    by_id = {r["run_id"]: r for r in history.list_scans(tmp_path)}
    assert by_id["r2"]["delta"]["new"] == 1, "a rewritten findings.json must never be served stale"


def test_scans_api_includes_new_fields(tmp_path):
    reg = tmp_path / "register.json"
    reg.write_text("[]", encoding="utf-8")
    _record(tmp_path, "r1", "scan code", [_finding("a")])
    client = TestClient(build_app(reg))
    row = client.get("/api/scans").json()[0]
    assert {"kind", "previous_run_id", "baseline", "delta"} <= set(row)
    detail = client.get("/api/scans/r1").json()
    assert detail["baseline"] is True and detail["kind"] == "scan code"


# --------------------------------------------------------------------------
# static assets are wired in
# --------------------------------------------------------------------------

def test_index_loads_scans_assets_and_nav_key():
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "js/views/scans-core" in index and "js/views/scans" in index and '"scans"' in index
    assert index.index("scans-core") < index.index('"js/views/scans"'), "core must load before the view"
    app = (STATIC / "app.js").read_text(encoding="utf-8")
    assert 'id: "scans"' in app and 'key: "s"' in app, "`g s` must keep reaching the scans view"
    for f in ("css/scans.css", "js/views/scans-core.js", "js/views/scans.js"):
        assert (STATIC / f).is_file()


def test_every_template_interpolation_in_the_scans_view_is_escaped_or_numeric():
    """Static audit: in scans.js / scans-core.js each `${...}` inside a template
    literal must be one of: an escaped value, a number formatter, an icon, a
    nested builder, a constant or a pure expression. This catches a raw
    `${f.title}` being added later."""
    risky = re.compile(r"\$\{\s*(?:[a-z]\w*\.)?(?:title|message|remediation|snippet|engagement|run_id|command|detail|target|host|path|tool|rule_id|notes|id|g|key)\s*\}")
    for name in ("js/views/scans.js", "js/views/scans-core.js"):
        src = (STATIC / name).read_text(encoding="utf-8")
        hits = risky.findall(src)
        assert not hits, f"{name}: unescaped interpolation of scan-derived field(s): {hits}"


# --------------------------------------------------------------------------
# JS logic (node)
# --------------------------------------------------------------------------

def js(expr: str):
    out = subprocess.run([NODE, str(RUNNER), expr], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


@needs_node
def test_health_never_calls_an_unrecorded_run_complete():
    cases = js("""[
      J.scansCore.health({tools:[], gaps:[]}).level,
      J.scansCore.health({tools:[{id:'a',status:'ok'},{id:'b',status:'ok'}], gaps:[]}).level,
      J.scansCore.health({tools:[{id:'a',status:'ok'},{id:'b',status:'skipped'}], gaps:[]}).level,
      J.scansCore.health({tools:[{id:'a',status:'ok'},{id:'b',status:'failed'}], gaps:[]}).level,
      J.scansCore.health({tools:[{id:'a',status:'ok'}], gaps:['x not covered']}).level,
      J.scansCore.health({tools:[{id:'a',status:'weird'}], gaps:[]}).level,
      J.scansCore.health({tools:[{id:'a',status:'failed'},{id:'b',status:'skipped'}], gaps:[]}).level
    ]""")
    assert cases == ["unverified", "complete", "partial", "degraded", "partial", "partial", "degraded"]


@needs_node
def test_zero_findings_is_only_clean_when_every_engine_ran():
    claims = js("""[
      J.scansCore.resultClaim({total:0, tools:[{id:'a',status:'ok'}], gaps:[]}),
      J.scansCore.resultClaim({total:0, tools:[{id:'a',status:'skipped'}], gaps:[]}),
      J.scansCore.resultClaim({total:0, tools:[], gaps:[]}),
      J.scansCore.resultClaim({total:3, tools:[], gaps:[]})
    ]""")
    assert claims[0]["clean"] is True and claims[0]["text"] == "Clean"
    for c in claims[1:3]:
        assert c["clean"] is False and "not a clean bill" in c["text"]
    assert claims[3]["text"] == "3 findings"


@needs_node
def test_baseline_is_not_reported_as_new_findings():
    r = js("""[
      J.scansCore.runDelta({baseline:true, delta:{new:9,fixed:0,same:0}}),
      J.scansCore.runDelta({baseline:false, previous_run_id:'p', delta:{new:2,fixed:1,same:5}}),
      J.scansCore.runDelta({previous_run_id:null, delta:{new:4,fixed:0,same:0}})
    ]""")
    assert r[0] == {"baseline": True, "new": 0, "fixed": 0, "same": 0}
    assert r[1] == {"baseline": False, "new": 2, "fixed": 1, "same": 5}
    assert r[2]["baseline"] is True
    html = js("J.scansCore.deltaHtml({baseline:true,total:9,delta:{new:9,fixed:0,same:0}})")
    assert "Baseline" in html and "+9" not in html


@needs_node
def test_sort_by_most_new_ranks_regressions_above_baselines():
    order = js("""J.scansCore.sortRuns([
      {run_id:'baseline', baseline:true, total:900, delta:{new:900,fixed:0,same:0}, finished_at:'2026-01-03'},
      {run_id:'regress',  baseline:false, previous_run_id:'x', total:12, delta:{new:7,fixed:0,same:5}, finished_at:'2026-01-02'},
      {run_id:'quiet',    baseline:false, previous_run_id:'y', total:5, delta:{new:0,fixed:0,same:5}, finished_at:'2026-01-04'}
    ], 'new').map(r => r.run_id)""")
    assert order == ["regress", "quiet", "baseline"]


@needs_node
def test_filter_group_and_latest_per_kind():
    r = js("""(() => {
      const runs = [
        {run_id:'a1', engagement:'alpha', command:'scan code', finished_at:'2026-01-01T00:00:00Z', tools:[{id:'s',status:'ok'}], gaps:[]},
        {run_id:'a2', engagement:'alpha', command:'scan code', finished_at:'2026-01-02T00:00:00Z', tools:[], gaps:[]},
        {run_id:'b1', engagement:'beta',  command:'scan recon --mode passive', finished_at:'2026-01-03T00:00:00Z', tools:[{id:'n',status:'skipped'}], gaps:[]}
      ];
      const C = J.scansCore;
      return {
        attention: C.filterRuns(runs, {health:'attention'}).map(x => x.run_id),
        complete:  C.filterRuns(runs, {health:'complete'}).map(x => x.run_id),
        kind:      C.filterRuns(runs, {kind:'scan recon'}).map(x => x.run_id),
        eng:       C.filterRuns(runs, {eng:'alpha'}).map(x => x.run_id),
        q:         C.filterRuns(runs, {q:'BETA'}).map(x => x.run_id),
        groups:    C.groupRuns(runs).map(g => [g.key, g.runs.length, g.attention, g.latest.run_id]),
        latest:    C.latestPerKind(runs).map(x => x.run_id)
      };
    })()""")
    assert r["attention"] == ["a2", "b1"] and r["complete"] == ["a1"]
    assert r["kind"] == ["b1"] and r["eng"] == ["a1", "a2"] and r["q"] == ["b1"]
    assert r["groups"] == [["beta", 1, 1, "b1"], ["alpha", 2, 1, "a2"]]
    assert r["latest"] == ["b1", "a2"]


@needs_node
def test_compare_with_previous_run_splits_new_fixed_same():
    r = js("""(() => {
      const C = J.scansCore;
      const prev = [{fingerprint:'k1',title:'one'},{fingerprint:'k2',title:'two'},{fingerprint:'k3',title:'three'}];
      const cur  = [{fingerprint:'k2',title:'two'},{fingerprint:'k3',title:'three'},{fingerprint:'k4',title:'four'}];
      const d = C.diff(cur, prev);
      return { fixed: d.fixed.map(f => f.fingerprint), added: [...d.newKeys], same: [...d.sameKeys].sort(),
               onlyNew: C.filterFindings(cur, {chg:'new'}, d).map(f => f.fingerprint),
               onlySame: C.filterFindings(cur, {chg:'same'}, d).map(f => f.fingerprint) };
    })()""")
    assert r == {"fixed": ["k1"], "added": ["k4"], "same": ["k2", "k3"], "onlyNew": ["k4"], "onlySame": ["k2", "k3"]}


@needs_node
def test_finding_filters_and_sorts():
    r = js("""(() => {
      const C = J.scansCore;
      const rows = [
        {title:'b', severity:'low', tool:'t1', confidence:'confirmed', status:'open', path:'z.py', line:1},
        {title:'a', severity:'critical', tool:'t2', confidence:'likely', status:'open', path:'a.py', line:2},
        {title:'c', severity:'critical', tool:'t1', confidence:'confirmed', status:'fixed', host:'h', target:'https://h/'}
      ];
      return {
        sev: C.filterFindings(rows, {sev:['critical']}).map(x => x.title),
        tool: C.filterFindings(rows, {tool:'t1'}).map(x => x.title),
        conf: C.filterFindings(rows, {conf:'likely'}).map(x => x.title),
        st: C.filterFindings(rows, {st:'fixed'}).map(x => x.title),
        q: C.filterFindings(rows, {q:'a.py'}).map(x => x.title),
        bySev: C.sortFindings(rows, 'severity', '').map(x => x.title),
        byTitle: C.sortFindings(rows, 'title', 'desc').map(x => x.title)
      };
    })()""")
    assert r["sev"] == ["a", "c"] and r["tool"] == ["b", "c"] and r["conf"] == ["a"] and r["st"] == ["c"] and r["q"] == ["a"]
    assert r["bySev"] == ["c", "a", "b"] and r["byTitle"] == ["c", "b", "a"]


EVIL = "<img src=x onerror=alert(1)>\\\"'><script>alert(2)</script>"


@needs_node
def test_every_scan_derived_string_is_escaped_in_the_builders():
    """History data comes from scan artifacts, which contain target-controlled
    text. Feed every field a builder reads an HTML/attribute-breakout payload
    and assert no live markup survives."""
    htmls = js("""(() => {
      const E = %s;
      const C = J.scansCore;
      const run = {run_id:E, finished_at:'2026-01-01T00:00:00Z', command:E, mode:E, engagement:E, kind:E,
        total:3, by_severity:{critical:1, high:2}, tools:[{id:E,status:E,detail:E,findings:1}], gaps:[E],
        delta:{new:1,fixed:0,same:1}, previous_run_id:E, baseline:false, lenses:[E]};
      const f = {title:E, severity:E, tool:E, confidence:E, status:E, path:E, line:3, host:E, target:E, endpoint:E, method:E,
        rule_id:E, cwe:[E], owasp:[E], message:E, remediation:E, snippet:E, category:E, fingerprint:E,
        extra:{evidence:E, also_reported_by:[E]}};
      return [C.runRowHtml(run), C.healthChip(run, {long:true}), C.deltaHtml(run), C.findingRowHtml(f, 0, {expanded:true, badge:'new'}),
              C.findingRowHtml(f, 1, {badge:'gone'}), C.findingDetailHtml(f, 2), C.sevBar({critical:1}), C.cls(E)];
    })()""" % json.dumps(EVIL))
    blob = "\n".join(htmls)
    assert "<img" not in blob and "<script" not in blob, "payload markup leaked into the output"
    assert "&lt;img" in blob and "&lt;script&gt;" in blob, "payload must be present but inert"
    # attribute breakout: the quote must never close an attribute and start a new one
    assert not re.search(r'="[^"]*"\s+onerror=', blob) and not re.search(r"\sonerror=", re.sub(r"&lt;img[^&]*", "", blob.replace("&lt;img src=x onerror", "")))
    # CSS-class context uses an allow-list, not escaping
    assert js("J.scansCore.cls(%s)" % json.dumps(EVIL)) == "imgsrcxonerroralert1scriptalert2script"


@needs_node
def test_row_markup_distinguishes_clean_from_unverified():
    clean = js("J.scansCore.runRowHtml({run_id:'c',command:'scan code',total:0,by_severity:{},tools:[{id:'s',status:'ok'}],gaps:[],baseline:true})")
    skipped = js("J.scansCore.runRowHtml({run_id:'s',command:'scan code',total:0,by_severity:{},tools:[{id:'semgrep',status:'skipped',detail:'not installed'}],gaps:[],baseline:true})")
    assert ">Clean<" in clean and "h-complete" in clean
    assert ">Clean<" not in skipped and "not a clean bill" in skipped and "h-partial" in skipped


# --------------------------------------------------------------------------
# contrast (static): the colour pairs scans.css uses, both themes
# --------------------------------------------------------------------------

def _tokens():
    css = (STATIC / "css" / "tokens.css").read_text(encoding="utf-8")

    def block(start):
        i = css.index(start)
        return css[i:css.index("}", i)]

    def vars_(b):
        return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", b))

    light = vars_(block(":root {"))
    dark = {**light, **vars_(block(':root[data-theme="dark"] {'))}
    return light, dark


def _lum(h: str) -> float:
    def f(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def _ratio(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


PAIRS = [
    ("text", "surface"), ("text-2", "surface"), ("text-2", "surface-2"), ("text-2", "bg"), ("text-2", "surface-3"),
    ("text-3", "surface"), ("accent-text", "surface"), ("accent-text", "surface-2"), ("accent-text", "accent-soft"),
    ("st-fixed-fg", "st-fixed-bg"), ("sev-medium-fg", "sev-medium-bg"), ("sev-critical-fg", "sev-critical-bg"),
    ("sev-info-fg", "sev-info-bg"), ("sev-low-fg", "sev-low-bg"), ("sev-high-fg", "sev-high-bg"),
    ("st-fixed-fg", "surface"), ("sev-high-fg", "surface"), ("sev-medium-fg", "surface"),
    ("text", "face-code-soft"), ("text", "face-recon-soft"), ("primary-text", "primary"),
]


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_scans_ui_colour_pairs_meet_wcag_aa(theme):
    light, dark = _tokens()
    t = light if theme == "light" else dark
    bad = [(a, b, round(_ratio(t[a], t[b]), 2)) for a, b in PAIRS if _ratio(t[a], t[b]) < 4.5]
    assert not bad, f"{theme}: below 4.5:1 -> {bad}"


def test_record_scan_persists_engine_status_and_quality(tmp_path):
    history.record_scan(
        tmp_path, run_id="r1", command="scan all", scope_manifest={"engagement": "e"}, findings=[],
        coverage={"engines": [{"id": "code", "status": "ran"}, {"id": "recon", "status": "skipped", "detail": "no hosts"}],
                  "quality": "degraded", "gaps": ["recon skipped"]},
    )
    meta = history.load_scan(tmp_path, "r1")["meta"]
    assert meta["engines"][1]["status"] == "skipped" and meta["quality"] == "degraded"


@needs_node
def test_engine_rows_count_toward_run_health():
    r = js("""[
      J.scansCore.health({engines:[{id:'code',status:'ran'}], tools:[], gaps:[]}).level,
      J.scansCore.health({engines:[{id:'code',status:'ran'},{id:'recon',status:'skipped'}], tools:[], gaps:[]}).level,
      J.scansCore.resultClaim({total:0, engines:[{id:'code',status:'ran'}], tools:[], gaps:[]}).clean,
      J.scansCore.resultClaim({total:0, engines:[{id:'code',status:'ran'},{id:'recon',status:'skipped'}], tools:[], gaps:[]}).clean
    ]""")
    assert r == ["complete", "partial", True, False]


def test_partial_record_is_visible_and_not_used_as_delta_baseline(tmp_path):
    _record(tmp_path, "old", "scan code", [_finding("old")])
    partial = tmp_path / "scans" / "broken"
    partial.mkdir(parents=True)
    (partial / "scan.json").write_text("{\"run_id\": \"broken\", \"command\": \"scan code\", \"finished_at\": \"2099-01-02T00:00:00Z\"}", encoding="utf-8")
    rows = {r["run_id"]: r for r in history.list_scans(tmp_path)}
    assert rows["broken"]["status"] == "partial"
    assert rows["broken"]["baseline"] is True
    assert rows["broken"]["delta"] == {"new": 0, "fixed": 0, "same": 0}
    assert rows["old"]["previous_run_id"] is None


def test_corrupt_scan_metadata_is_listed_and_loadable_as_partial(tmp_path):
    path = tmp_path / "scans" / "corrupt"
    path.mkdir(parents=True)
    (path / "scan.json").write_text("not json", encoding="utf-8")
    rows = history.list_scans(tmp_path)
    assert rows and rows[0]["run_id"] == "corrupt" and rows[0]["status"] == "partial"
    detail = history.load_scan(tmp_path, "corrupt")
    assert detail["status"] == "partial" and detail["findings"] == []


def test_scan_run_id_cannot_escape_history_directory(tmp_path):
    assert history.load_scan(tmp_path, "..") is None
    assert history.load_scan(tmp_path, "../register.json") is None
    assert history.load_scan(tmp_path, "nested\\run") is None


def test_load_scan_returns_new_and_fixed_finding_lists(tmp_path):
    _record(tmp_path, "r1", "scan code", [_finding("old"), _finding("same", "same.py")])
    _record(tmp_path, "r2", "scan code", [_finding("same", "same.py"), _finding("new", "new.py")])
    detail = history.load_scan(tmp_path, "r2")
    assert [f["title"] for f in detail["new_findings"]] == ["new"]
    assert [f["title"] for f in detail["fixed_findings"]] == ["old"]


def test_failed_atomic_history_write_leaves_no_final_or_temp_record(tmp_path, monkeypatch):
    original = history._write_json
    calls = {"n": 0}

    def fail_after_first(path, value):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated disk failure")
        return original(path, value)

    monkeypatch.setattr(history, "_write_json", fail_after_first)
    with pytest.raises(OSError):
        _record(tmp_path, "atomic", "scan code", [_finding("x")])
    scans = tmp_path / "scans"
    assert not (scans / "atomic").exists()
    assert not [p for p in scans.iterdir() if p.name.startswith(".atomic.tmp-")]
