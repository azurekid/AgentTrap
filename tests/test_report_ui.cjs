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
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, callback) { this.events[name] = callback; }
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
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../web/static/fingerprints.js"), "utf8"), {
    document: { getElementById: (id) => elements[id], createElement: (tag) => new Element(tag) },
    location: { search: "" }, history: { replaceState() {} },
    AbortController, URLSearchParams,
    fetch: async (url) => {
      requests.push(url);
      return { status, ok: status === 200, json: async () => data };
    },
  });
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
