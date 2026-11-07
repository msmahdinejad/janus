// Loads the dashboard's pure-logic scripts into a bare vm context (no DOM, no
// network) and evaluates one JS expression, printing its JSON result.
// Used by tests/test_dashboard_scans_ui.py; skipped there when node is absent.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.join(__dirname, "..", "..", "janus", "dashboard", "static", "js");
const ctx = { console, URLSearchParams, Date, Math, JSON, Set, Map, Number, String, Object, Array, RegExp };
ctx.window = ctx;
ctx.navigator = { platform: "test" };
vm.createContext(ctx);
for (const f of ["util.js", "icons.js", "charts.js", "views/shared.js", "views/scans-core.js"]) {
  vm.runInContext(fs.readFileSync(path.join(root, f), "utf8"), ctx, { filename: f });
}
const out = vm.runInContext(process.argv[2], ctx, { filename: "expr" });
process.stdout.write(JSON.stringify(out === undefined ? null : out));
