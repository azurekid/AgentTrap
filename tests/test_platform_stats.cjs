const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const script = fs.readFileSync(path.join(__dirname, "../web/static/fx.js"), "utf8");

async function load({ activityFails = false, registryFails = false, invalid = false } = {}) {
  const ids = ["stat-detectors", "total-files", "total-findings", "unique-skills",
    "unique-complete", "unique-mcp", "uniqueness-status", "statistics-error"];
  const elements = Object.fromEntries(ids.map((id) => [id, { textContent: "-", dataset: {}, hidden: true }]));
  const listeners = {};
  const requests = [];
  let findings = invalid ? -1 : 7;
  const context = {
    location: { hash: "" },
    matchMedia: () => ({ matches: true }),
    document: {
      getElementById: (id) => elements[id] || null,
      addEventListener: (event, callback) => { listeners[event] = callback; },
    },
    console: { error() {} },
    setInterval() {},
    fetch: async (url) => {
      requests.push(url);
      if (url === "/api/policy") return { ok: true, json: async () => ({ detectors: 81 }) };
      if (url === "/api/statistics") return { ok: !activityFails, status: 503,
        json: async () => ({ files: 100, findings: 9999 }) };
      assert.equal(url, "/api/statistics/unique");
      return { ok: !registryFails, status: 503, json: async () => ({
        counts: { findings, skill_snapshots: 9, complete_skill_versions: 4, mcp_snapshots: 2 },
        since: null,
      }) };
    },
  };
  vm.runInNewContext(script, context);
  await new Promise((resolve) => setImmediate(resolve));
  return { elements, requests, refresh: () => listeners["skillvenom:scan-complete"](), update: (value) => { findings = value; } };
}

test("primary metrics use unique findings, one registry request, and refresh after scans", async () => {
  const state = await load();
  assert.equal(state.elements["total-files"].textContent, "100");
  assert.equal(state.elements["total-findings"].textContent, "7");
  assert.equal(state.elements["unique-skills"].textContent, "9");
  assert.equal(state.elements["stat-detectors"].textContent, "81");
  assert.equal(state.requests.filter((url) => url === "/api/statistics/unique").length, 1);
  assert.equal(state.elements["statistics-error"].hidden, true);
  state.update(8);
  await state.refresh();
  assert.equal(state.elements["total-findings"].textContent, "8");
});

test("activity outages do not suppress available unique registry counts", async () => {
  const { elements } = await load({ activityFails: true });
  assert.equal(elements["total-files"].textContent, "Unavailable");
  assert.equal(elements["total-findings"].textContent, "7");
  assert.equal(elements["statistics-error"].hidden, false);
});

test("registry outages and invalid counters fail explicitly, never falling back to repeat hits", async () => {
  for (const options of [{ registryFails: true }, { invalid: true }]) {
    const { elements } = await load(options);
    assert.equal(elements["total-files"].textContent, "100");
    for (const id of ["total-findings", "unique-skills", "unique-complete", "unique-mcp"]) {
      assert.equal(elements[id].textContent, "Unavailable");
    }
    assert.equal(elements["statistics-error"].hidden, false);
  }
});
