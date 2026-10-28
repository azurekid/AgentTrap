"use strict";
(() => {
  const form = document.getElementById("fingerprint-form");
  const input = document.getElementById("fingerprint-hash");
  const status = document.getElementById("lookup-status");
  const result = document.getElementById("lookup-result");
  let active;
  function element(tag, text, className = "") {
    const node = document.createElement(tag);
    node.textContent = text;
    node.className = className;
    return node;
  }
  async function lookup(value) {
    const hash = value.trim().toLowerCase();
    input.value = hash;
    if (active) active.abort();
    result.hidden = true;
    result.replaceChildren();
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      status.textContent = "Enter a full 64-character SHA256 content fingerprint.";
      return;
    }
    const controller = new AbortController();
    active = controller;
    status.textContent = "Searching central registry...";
    history.replaceState(null, "", `/fingerprints?hash=${hash}`);
    try {
      const response = await fetch(`/api/fingerprints/${hash}`, { signal: controller.signal, cache: "no-store" });
      if (controller.signal.aborted) return;
      if (response.status === 404) {
        status.textContent = "No matching snapshot or indexed file-text hash found. Older scans need a rescan to index file-text hashes. This is not evidence that the content is safe.";
        return;
      }
      if (response.status === 429) throw new Error("Fingerprint lookup limit reached. Wait a minute before searching again.");
      if (!response.ok) throw new Error("Central fingerprint lookup is temporarily unavailable. Try again later.");
      let data = await response.json();
      if (controller.signal.aborted) return;
      status.textContent = "Fingerprint found in the central registry.";
      if (data.match_type === "inspected_text") {
        status.textContent = `File-text hash found in ${data.matches.length} recorded snapshot(s). Assessments cover the containing snapshots, not this file alone.`;
        if (data.matches.length > 1) {
          result.append(element("h2", "Matching snapshots"));
          for (const match of data.matches) {
            const link = element("a", match.content_id, "fingerprint-value");
            link.href = `/fingerprints?hash=${match.content_id}`;
            const row = element("p", "");
            row.append(link);
            result.append(row);
          }
          result.hidden = false;
          return;
        }
        data = data.matches[0];
      }
      result.append(element("h2", "Stored fingerprint report"), element("code", data.content_id),
        element("p", data.disclaimer, "meta"));
      const kinds = { skill_snapshot: "Skill snapshot", mcp_snapshot: "MCP definition snapshot", agent_file: "Agent file" };
      result.append(element("h3", kinds[data.kind] || data.kind));
      if (!data.report) {
        result.append(element("p", "This fingerprint predates stored assessments. Rescan the matching content to add an assessment. No findings or safety conclusion can be inferred."));
      } else {
        const report = data.report;
        result.append(element("p", `${report.findings} signal occurrences across ${report.file_count} inspected files.`),
          element("p", `Signal risk score: ${report.assessment.score === null ? "Not scored" : `${report.assessment.score}/100`}. Method: ${report.assessment.version}. Higher means more distinct rule evidence, not malware probability.`),
          element("p", report.severities.CRITICAL || report.severities.HIGH
            ? "HIGH or CRITICAL signals recorded: manual review required."
            : "No HIGH or CRITICAL signals recorded. This is not approval.", "warning"),
          element("p", `Inspection status: ${report.inspection_status}. Package coverage: ${report.package_complete ? "complete supported package" : "snapshot only, not a complete-package claim"}.`),
          element("p", "Coverage status reflects the originating full inspection; a partial result cannot establish that this snapshot is clean.", "meta"),
          element("p", `First stored assessment: ${new Date(report.first_seen).toLocaleString()}. Latest recorded assessment: ${new Date(report.last_seen).toLocaleString()}.`, "meta"),
          element("p", `Evaluation fingerprint: ${report.evaluation_id}`, "meta"),
          element("p", `Detector fingerprint: ${report.detector_sha256 || "Unavailable"}`, "meta"));
        const counts = element("div", "", "lookup-counts");
        for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
          counts.append(element("span", `${severity}: ${report.severities[severity]}`, `badge ${severity.toLowerCase()}`));
        }
        result.append(counts);
        const list = element("ul", "");
        for (const rule of report.rules) list.append(element("li", `${rule.severity} | ${rule.rule} | ${rule.count} occurrence(s)`));
        result.append(list);
        for (const category of report.assessment.categories.filter((category) => category.findings)) {
          result.append(element("h3", category.name), element("p", `${category.findings} signals. ${category.guidance}`));
        }
        result.append(element("h3", "Inspection coverage"));
        const checks = element("ul", "");
        for (const check of report.assessment.checks) checks.append(element("li", `${check.performed ? "Performed" : "Not performed"}: ${check.name}`));
        result.append(checks);
      }
      result.hidden = false;
    } catch (error) {
      if (!controller.signal.aborted) status.textContent = error.message || "Fingerprint lookup failed.";
    }
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    lookup(input.value);
  });
  const initial = new URLSearchParams(location.search).get("hash");
  if (initial) lookup(initial);
})();
