"use strict";

function buildSarif(report) {
  if (!report || !Array.isArray(report.files)) throw new Error("A valid inspection report is required.");
  const levels = { CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note" };
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const rules = new Map();
  const results = [];
  for (const file of report.files) {
    if (typeof file.path !== "string" || !Array.isArray(file.findings)) throw new Error("Invalid file evidence.");
    const uri = file.path.replaceAll("\\", "/").split("/").map(encodeURIComponent).join("/");
    for (const hit of file.findings) {
      if (typeof hit.rule !== "string" || typeof hit.message !== "string"
        || !Object.hasOwn(levels, hit.severity) || !Number.isSafeInteger(hit.line) || hit.line < 0) {
        throw new Error("Invalid finding evidence.");
      }
      const previous = rules.get(hit.rule);
      if (!previous || rank[hit.severity] > rank[previous.properties.severity]) {
        rules.set(hit.rule, {
          id: hit.rule, shortDescription: { text: hit.message },
          defaultConfiguration: { level: levels[hit.severity] },
          properties: { severity: hit.severity, tags: ["security", ...(hit.category ? [hit.category] : [])] },
        });
      }
      const location = { physicalLocation: { artifactLocation: { uri } } };
      if (hit.json_pointer) {
        location.logicalLocations = [{ fullyQualifiedName: hit.json_pointer, kind: "member" }];
      } else if (hit.line > 0) {
        location.physicalLocation.region = { startLine: hit.line };
      }
      results.push({
        ruleId: hit.rule, level: levels[hit.severity], message: { text: hit.message }, locations: [location],
        ...(hit.id && { partialFingerprints: { "skillvenomFinding/v1": hit.id } }),
        properties: {
          severity: hit.severity, evidenceSource: hit.evidence_source || "raw",
          ...(hit.category && { category: hit.category }),
          ...(hit.json_pointer && { jsonPointer: hit.json_pointer }),
          ...(hit.encoding_chain && {
            encodingChain: hit.encoding_chain, decodedLine: hit.decoded_line, encodedOffset: hit.encoded_offset,
          }),
          ...(hit.atlas && { mitreAtlas: hit.atlas }),
          ...(hit.owasp && { owaspAsi: hit.owasp }),
        },
      });
    }
  }
  const complete = report.status === "complete";
  const invocation = { executionSuccessful: complete };
  if (!complete) {
    invocation.toolExecutionNotifications = [{
      level: "warning", message: { text: "Inspection was incomplete or had no target files. This is not a clean result." },
    }];
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "SkillVenom", informationUri: "https://github.com/azurekid/AgentTrap",
        rules: [...rules.values()].sort((a, b) => a.id.localeCompare(b.id)),
      } },
      invocations: [invocation], results,
      properties: {
        scanStatus: report.status || "unknown",
        detectorSha256: report.provenance?.detector_sha256 || null,
        methodology: report.evaluation?.version || null,
        inventory: report.inventory || null,
        skipped: report.skipped || [],
        disclaimer: "Static rule evidence, not a safety certification or CVSS assessment. Snippets and original contents are excluded.",
      },
    }],
  };
}

if (typeof module !== "undefined" && module.exports) module.exports = { buildSarif };
