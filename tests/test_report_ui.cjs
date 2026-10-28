const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
  constructor(tag = "div") {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.events = {};
    this.value = "";
    this.open = false;
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, callback) { this.events[name] = callback; }
  focus() { this.focused = true; }
  get firstChild() { return this.children[0]; }
  get childElementCount() { return this.children.length; }
}

function setup(report) {
  const elements = {};
  const context = vm.createContext({
    document: { getElementById: (id) => elements[id] || null, createElement: (tag) => new Element(tag) },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/static/app.js"), "utf8"), context);
  for (const id of ["evaluation", "finding-category", "evaluation-summary", "evaluation-categories",
    "evaluation-checks", "evaluation-provenance", "snapshot-review", "snapshot-cards", "fingerprint-status",
    "snapshot-search", "snapshot-filter", "snapshot-review-summary"]) elements[id] = new Element();
  context.inputReport = report;
  vm.runInContext("report = inputReport;", context);
  return { elements, run: (code) => vm.runInContext(code, context) };
}

function descendants(element) {
  return [element, ...element.children.flatMap(descendants)];
}

function setupScanner(response = { ok: true }) {
  const ids = ["scan-form", "private-repo", "repo-token", "token-field", "repository",
    "upload-tab", "repo-tab", "paste-tab", "upload-panel", "repo-panel", "paste-panel",
    "files", "folder", "dropzone", "file-list", "skill-content", "error", "console",
    "console-state", "scan-button", "progress", "workflows"];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element()]));
  const tabs = new Element();
  const requests = [];
  const saved = new Map();
  const destinations = [];
  const context = vm.createContext({
    document: {
      getElementById: (id) => elements[id] || null,
      createElement: (tag) => new Element(tag), createTextNode: (text) => ({ textContent: text }),
      querySelector: () => tabs, body: new Element(), dispatchEvent() {},
    },
    location: { search: "", assign: (url) => destinations.push(url) },
    sessionStorage: { setItem: (key, value) => saved.set(key, value) },
    URLSearchParams, Blob, FormData, AbortSignal, Event,
    fetch: async (url, options) => {
      requests.push({ url, ...options });
      assert.equal(elements["skill-content"].disabled, true);
      return { ok: response.ok, headers: new Headers({ "content-type": "application/json" }),
        json: async () => response.ok ? { status: "complete" } : { detail: "Scanner unavailable" } };
    },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/static/app.js"), "utf8"), context);
  return { elements, tabs, requests, saved, destinations,
    run: (code) => vm.runInContext(code, context),
    submit: () => elements["scan-form"].events.submit({ preventDefault() {} }) };
}

test("paste submits exact skill text through upload pipeline and opens the stored report", async () => {
  const { elements, requests, saved, destinations, run, submit } = setupScanner();
  run("changeMode('paste')");
  const content = "---\nname: Review helper\n---\n\n  caf\u00e9\n";
  elements["skill-content"].value = content;
  await submit();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "/api/scan/files");
  const body = requests[0].body;
  const file = body.get("files");
  assert.equal(file.name, "SKILL.md");
  assert.equal(await file.text(), content);
  assert.equal(body.get("discover"), "false");
  assert.equal(body.get("include_workflows"), "false");
  assert.equal(saved.get("skillvenom:report"), '{"status":"complete"}');
  assert.deepEqual(destinations, ["/report"]);
  assert.equal(elements["skill-content"].disabled, false);
  assert.equal(elements["skill-content"].value, content);
});

test("paste rejects whitespace and enforces UTF-8 bytes with an inclusive 256 KiB limit", async () => {
  const { elements, requests, run, submit } = setupScanner();
  run("changeMode('paste')");
  elements["skill-content"].value = " \n\t ";
  await submit();
  assert.match(elements.error.textContent, /Paste skill content/);
  elements["skill-content"].value = "\u00e9".repeat(131073);
  await submit();
  assert.match(elements.error.textContent, /256 KiB/);
  assert.equal(requests.length, 0);
  elements["skill-content"].value = "\u00e9".repeat(131072);
  await submit();
  assert.equal(requests[0].body.get("files").size, 256 * 1024);
});

test("paste failures retain editable text and expose the server error", async () => {
  const { elements, destinations, run, submit } = setupScanner({ ok: false });
  run("changeMode('paste')");
  elements["skill-content"].value = "Review this skill";
  await submit();
  assert.equal(elements.error.hidden, false);
  assert.equal(elements.error.textContent, "Scanner unavailable");
  assert.equal(elements["skill-content"].disabled, false);
  assert.equal(elements["skill-content"].value, "Review this skill");
  assert.equal(destinations.length, 0);
});

test("three source tabs support directional wrapping, Home, End and preserved drafts", () => {
  const { elements, tabs, run } = setupScanner();
  elements["skill-content"].value = "My draft";
  const key = (key) => tabs.events.keydown({ key, preventDefault() {} });
  key("ArrowLeft");
  assert.equal(run("mode"), "paste");
  assert.equal(elements["paste-panel"].hidden, false);
  assert.equal(elements["paste-tab"].attributes["aria-selected"], "true");
  assert.equal(elements["repository"].disabled, true);
  key("Home");
  assert.equal(run("mode"), "upload");
  key("ArrowRight");
  assert.equal(run("mode"), "repo");
  assert.equal(elements["repository"].disabled, false);
  assert.equal(elements["skill-content"].disabled, true);
  key("End");
  assert.equal(run("mode"), "paste");
  assert.equal(elements["skill-content"].value, "My draft");
});

const artifact = {
  kind: "agent_file", root: "AGENTS.md", content_id: "a".repeat(64), evaluation_id: "b".repeat(64),
  files: [{ path: "AGENTS.md" }], coverage_notes: [],
};
const file = { path: "AGENTS.md", findings: [{ severity: "HIGH" }] };

test("collapsed snapshot exposes full searchable content fingerprint and copy action", () => {
  const { elements, run } = setup({ artifacts: [artifact], files: [file], status: "complete" });
  run("renderSnapshotReview()");
  const card = elements["snapshot-cards"].firstChild;
  assert.equal(card.open, false);
  const summary = card.firstChild;
  const nodes = descendants(summary);
  assert.ok(nodes.some((item) => item.tag === "code" && item.textContent === artifact.content_id));
  assert.ok(nodes.some((item) => item.href === `/fingerprints?hash=${artifact.content_id}`));
  assert.ok(nodes.some((item) => item.tag === "button" && item.textContent === "Copy"));
});

test("clean snapshots remain hidden", () => {
  const { elements, run } = setup({ artifacts: [artifact], files: [{ ...file, findings: [] }] });
  run("renderSnapshotReview()");
  assert.equal(elements["snapshot-review"].hidden, true);
  assert.equal(elements["snapshot-cards"].children.length, 0);
});

test("medium-only snapshots explain why their fingerprints are not centrally stored", () => {
  const { elements, run } = setup({
    artifacts: [{ ...artifact, seen_before: null, registry_status: "not_eligible" }],
    files: [{ ...file, findings: [{ severity: "MEDIUM" }] }],
  });
  run("renderSnapshotReview()");
  const nodes = descendants(elements["snapshot-cards"]);
  assert.ok(nodes.some((item) => item.textContent === "Not centrally stored"));
  assert.ok(nodes.some((item) => item.textContent?.includes("only snapshots with HIGH or CRITICAL findings")));
});

test("inspection summary uses exact score and category counts, with collapsed guidance", () => {
  const evaluation = {
    score: 20, decision: "review_required", highest_severity: "HIGH",
    categories: [
      { id: "instruction-control", name: "Instruction control", findings: 3, highest_severity: "HIGH", guidance: "Review overrides." },
      { id: "credentials", name: "Credentials", findings: 0 },
    ],
    checks: [{ name: "Pattern analysis", performed: true }, { name: "Runtime execution", performed: false }],
  };
  const { elements, run } = setup({ evaluation, files: [file], status: "complete" });
  run("renderEvaluation()");
  const overview = descendants(elements["evaluation-summary"]);
  assert.ok(overview.some((item) => item.tag === "strong" && item.textContent === "20/100"));
  assert.equal(overview.find((item) => item.tag === "meter").value, 20);
  const rows = descendants(elements["evaluation-categories"]);
  assert.equal(rows.find((item) => item.tag === "meter").value, 3);
  assert.equal(rows.find((item) => item.tag === "details").open, false);
  assert.equal(elements["evaluation-checks"].children.length, 2);
  evaluation.score = null;
  run("report.status = 'partial'; renderEvaluation()");
  assert.equal(descendants(elements["evaluation-summary"]).filter((item) => item.tag === "meter").length, 0);
  assert.ok(descendants(elements["evaluation-summary"]).some((item) => item.textContent === "Not scored"));
});

async function lookupResponse(data, status = 200) {
  const elements = Object.fromEntries(["fingerprint-form", "fingerprint-hash", "lookup-status", "lookup-result"]
    .map((id) => [id, new Element()]));
  const requests = [];
  const context = vm.createContext({
    document: { getElementById: (id) => elements[id], createElement: (tag) => new Element(tag),
      createElementNS: (_, tag) => new Element(tag) },
    requestAnimationFrame: (callback) => callback(),
    location: { search: "" }, history: { replaceState() {} },
    AbortController, URLSearchParams,
    fetch: async (url) => {
      requests.push(url);
      return { status, ok: status === 200, json: async () => data };
    },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/static/radar.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/static/fingerprints.js"), "utf8"), context);
  elements["fingerprint-hash"].value = "A".repeat(64);
  elements["fingerprint-form"].events.submit({ preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  return { elements, requests };
}

test("file-text search shows all containing snapshots instead of choosing one", async () => {
  const matches = ["b", "c"].map((char) => ({ content_id: char.repeat(64) }));
  const { elements, requests } = await lookupResponse({ match_type: "inspected_text", matches });
  assert.equal(requests[0], `/api/fingerprints/${"a".repeat(64)}`);
  assert.equal(elements["lookup-result"].hidden, false);
  const links = descendants(elements["lookup-result"]).filter((item) => item.tag === "a");
  assert.deepEqual(links.map((link) => link.href), matches.map((match) => `/fingerprints?hash=${match.content_id}`));
  assert.match(elements["lookup-status"].textContent, /2 recorded snapshot/);
});

test("missing hash explains older indexing limitations without implying safety", async () => {
  const { elements } = await lookupResponse(null, 404);
  assert.equal(elements["lookup-result"].hidden, true);
  assert.match(elements["lookup-status"].textContent, /Older scans need a rescan/);
  assert.match(elements["lookup-status"].textContent, /not evidence.*safe/);
});

test("public report renders visual metrics and untrusted excerpts only as code text", async () => {
  const snippet = '<img src=x onerror="alert(1)">';
  const report = {
    name: "<script>self-declared</script>", kind: "skill_snapshot", findings: 3, file_count: 2,
    inspection_status: "complete", first_seen: "2026-10-28T12:00:00Z", last_seen: "2026-10-28T12:00:00Z",
    severities: { CRITICAL: 0, HIGH: 3, MEDIUM: 0, LOW: 0 },
    assessment: {
      score: 20, version: "signal-risk-v1",
      categories: [{ name: "Instruction control", findings: 3, highest_severity: "HIGH", guidance: "Review overrides." }],
      checks: [{ name: "Static analysis", performed: true }, { name: "Runtime execution", performed: false }],
    },
    evidence: { excerpts: [{ rule: "PROMPT-INJECTION", severity: "HIGH", snippet, line: 4, source: "raw" }], omitted: 2 },
    atlas: { source: "Recorded ATLAS mapping", technique_count: 1,
      tactics: [{ key: "initial-access", name: "Initial Access", findings: 3 },
        { key: "execution", name: "Execution", findings: 0 },
        { key: "impact", name: "Impact", findings: 1 }] },
  };
  const { elements } = await lookupResponse({ content_id: "a".repeat(64), kind: "skill_snapshot", report });
  assert.equal(elements["lookup-result"].hidden, false);
  const nodes = descendants(elements["lookup-result"]);
  assert.ok(nodes.some((item) => item.tag === "meter" && item.value === 20));
  assert.ok(nodes.some((item) => item.tag === "meter" && item.value === 3));
  assert.ok(nodes.some((item) => item.tag === "svg" && item.attributes["aria-label"] === "Finding occurrences per MITRE ATLAS tactic"));
  const labels = nodes.filter((item) => item.tag === "h3").map((item) => item.textContent);
  assert.ok(labels.includes("MITRE ATLAS attack surface"));
  assert.ok(labels.includes("Findings"));
  const riskPosition = nodes.findIndex((item) => item.className === "evaluation-overview lookup-risk");
  const findingsPosition = nodes.findIndex((item) => item.className === "lookup-findings");
  assert.ok(riskPosition < findingsPosition);
  assert.ok(nodes.some((item) => item.tag === "summary" && item.textContent === "What does this score mean?"));
  assert.ok(nodes.some((item) => item.textContent?.includes("Critical 40, High 20, Medium 5, Low 1")));
  assert.ok(nodes.some((item) => item.tag === "code" && item.textContent === snippet));
  assert.equal(nodes.filter((item) => ["img", "script"].includes(item.tag)).length, 0);
  assert.ok(nodes.some((item) => item.textContent === report.name));
  assert.ok(nodes.some((item) => typeof item.textContent === "string" && item.textContent.includes("2 additional finding excerpts omitted")));
  delete report.evidence;
  delete report.atlas;
  const legacy = await lookupResponse({ content_id: "a".repeat(64), kind: "skill_snapshot", report });
  assert.ok(descendants(legacy.elements["lookup-result"]).some((item) => item.textContent?.includes("No excerpts stored")));
  assert.ok(descendants(legacy.elements["lookup-result"]).some((item) => item.textContent?.includes("no stored ATLAS mapping")));
});

test("archive-success notice is not rendered but storage errors remain visible", () => {
  const script = fs.readFileSync(path.join(__dirname, "../web/static/app.js"), "utf8");
  assert.equal(script.includes("high-risk file(s) retained in the private investigation archive"), false);
  assert.ok(script.includes('report.archive.status === "failed"'));
  assert.ok(script.includes('report.archive.message'));
});

test("shared spiderweb draws all axes and preserves exact count labels, including empty results", () => {
  const context = vm.createContext({
    document: { createElementNS: (_, tag) => new Element(tag) },
    requestAnimationFrame: (callback) => callback(),
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/static/radar.js"), "utf8"), context);
  const tactics = Array.from({ length: 11 }, (_, i) => ({ key: `tactic-${i}`, name: `Tactic ${i}`, findings: i === 3 ? 30 : 0 }));
  context.tactics = tactics;
  context.radar = new Element("svg");
  vm.runInContext("AgentLensRadar.draw(radar, tactics)", context);
  let nodes = descendants(context.radar);
  assert.equal(nodes.filter((item) => item.tag === "line").length, 11);
  assert.equal(nodes.filter((item) => item.attributes.class === "node").length, 1);
  assert.ok(nodes.some((item) => item.textContent === "30 findings"));
  assert.ok(nodes.filter((item) => item.tag === "polygon").every((item) => !/NaN|Infinity/.test(item.attributes.points)));
  tactics[3].findings = 0;
  vm.runInContext("AgentLensRadar.draw(radar, tactics)", context);
  nodes = descendants(context.radar);
  assert.equal(nodes.filter((item) => item.attributes.class === "node").length, 0);
  assert.ok(nodes.filter((item) => item.tag === "polygon").every((item) => !/NaN|Infinity/.test(item.attributes.points)));
});
