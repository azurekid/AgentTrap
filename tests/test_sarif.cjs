"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { buildSarif } = require("../web/static/sarif.js");

function finding(extra = {}) {
  return { rule: "PROMPT-INJECTION", message: "Instruction override", severity: "HIGH",
    category: "instruction-control", line: 4, id: "a".repeat(64), snippet: "DO NOT EXPORT THIS", ...extra };
}
function report(findings = [finding()], status = "complete") {
  return { status, files: [{ path: "skills/a #?/SKILL.md", findings }], skipped: [],
    provenance: { detector_sha256: "b".repeat(64) }, evaluation: { version: "signal-risk-v1" } };
}

test("SARIF uses real locations, URI encoding, distinct rules, fingerprints and severity levels", () => {
  const sarif = buildSarif(report([finding(), finding({ severity: "CRITICAL" }),
    finding({ rule: "UNLISTED-DOMAIN", severity: "LOW" }), finding({ severity: "MEDIUM" })]));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "AgentLens");
  assert.equal(run.tool.driver.rules.length, 2);
  assert.equal(run.tool.driver.rules[0].properties.severity, "CRITICAL");
  assert.equal(run.results.length, 4);
  assert.deepEqual(run.results.map(f => f.level), ["error", "error", "note", "warning"]);
  const hit = run.results[0];
  assert.equal(hit.locations[0].physicalLocation.artifactLocation.uri, "skills/a%20%23%3F/SKILL.md");
  assert.equal(hit.locations[0].physicalLocation.region.startLine, 4);
  assert.equal(hit.partialFingerprints["skillvenomFinding/v1"], "a".repeat(64));
  assert.equal(run.properties.detectorSha256, "b".repeat(64));
  assert.equal(run.invocations[0].executionSuccessful, true);
  assert.ok(!JSON.stringify(sarif).includes("DO NOT EXPORT THIS"));
  assert.ok(!JSON.stringify(sarif).includes("security-severity"));
});

test("decoded JSON has a logical pointer and never a fictitious physical line", () => {
  const hit = buildSarif(report([finding({ line: 0, json_pointer: "/tools/0/description",
    evidence_source: "decoded_payload", encoding_chain: ["base64"], decoded_line: 2, encoded_offset: 4 })])).runs[0].results[0];
  assert.equal(hit.locations[0].physicalLocation.region, undefined);
  assert.equal(hit.locations[0].logicalLocations[0].fullyQualifiedName, "/tools/0/description");
  assert.deepEqual(hit.properties.encodingChain, ["base64"]);
  assert.equal(hit.properties.decodedLine, 2);
  assert.equal(hit.properties.encodedOffset, 4);
});

test("line zero without a pointer has only an artifact location", () => {
  assert.equal(buildSarif(report([finding({ line: 0 })])).runs[0].results[0].locations[0].physicalLocation.region, undefined);
});

for (const status of ["partial", "no_targets", undefined]) {
  test(`incomplete status ${status} is not a successful clean scan`, () => {
    const input = report([], status);
    input.status = status;
    const run = buildSarif(input).runs[0];
    assert.equal(run.invocations[0].executionSuccessful, false);
    assert.match(run.invocations[0].toolExecutionNotifications[0].message.text, /not a clean result/);
  });
}

test("older reports without fingerprint or evaluation metadata still export", () => {
  const run = buildSarif({ status: "complete", files: [{ path: "SKILL.md", findings: [
    { rule: "PROMPT-INJECTION", message: "Review", severity: "HIGH", line: 1 },
  ] }] }).runs[0];
  assert.equal(run.results[0].partialFingerprints, undefined);
  assert.equal(run.properties.detectorSha256, null);
});

test("invalid inputs fail explicitly rather than export a clean empty result", () => {
  assert.throws(() => buildSarif({}), /valid inspection/);
  assert.throws(() => buildSarif(report([finding({ severity: "SAFE" })])), /Invalid finding/);
  assert.throws(() => buildSarif(report([finding({ line: -1 })])), /Invalid finding/);
});

test("file exports identify their scope rather than imply full-repository coverage", () => {
  const input = report();
  input.view_scope = { kind: "file", path: "SKILL.md", snapshot_scope: "containing package from full inspection" };
  assert.deepEqual(buildSarif(input).runs[0].properties.viewScope, input.view_scope);
});
