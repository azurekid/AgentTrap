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
  function meter(value, max, label) {
    const bar = element("meter", "", "evaluation-meter");
    bar.min = 0;
    bar.max = max;
    bar.value = value;
    bar.setAttribute("aria-label", label);
    return bar;
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
        status.textContent = "No matching snapshot or indexed file-text hash found. Only HIGH/CRITICAL snapshots are registered. Older scans need a rescan to index file-text hashes. This is not evidence that the content is safe.";
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
            if (match.report?.name) row.append(element("strong", `${match.report.name} (self-declared)`), element("br", ""));
            row.append(link);
            result.append(row);
          }
          result.hidden = false;
          return;
        }
        data = data.matches[0];
      }
      const identity = element("header", "", "lookup-identity");
      identity.append(element("p", "CONTENT IDENTITY", "label"), element("h2", "Fingerprint report"),
        element("code", data.content_id, "lookup-hash"));
      const kinds = { skill_snapshot: "Skill snapshot", mcp_snapshot: "MCP definition snapshot", agent_file: "Agent file" };
      identity.append(element("span", kinds[data.kind] || data.kind, "lookup-kind"));
      result.append(identity);
      if (!data.report) {
        result.append(element("p", "This fingerprint predates stored assessments. Rescan the matching content to add an assessment. No findings or safety conclusion can be inferred."));
      } else {
        const report = data.report;
        identity.append(element("h3", report.name || "Unnamed snapshot", "lookup-name"),
          element("p", report.name ? "Self-declared frontmatter name. Not verified publisher identity or ownership."
            : "This snapshot has no supported name metadata, or predates name indexing. Rescan to refresh metadata.", "meta"));
        const overview = element("section", "", "evaluation-overview lookup-risk");
        const score = element("div", "", "evaluation-score");
        score.append(element("span", "Signal risk", "meta"),
          element("strong", report.assessment.score === null ? "Not scored" : `${report.assessment.score}/100`));
        if (report.assessment.score !== null) score.append(meter(report.assessment.score, 100, "Signal risk out of 100"));
        const decision = element("div", "", "evaluation-decision");
        decision.append(element("p", "STATIC INSPECTION", "label"),
          element("h3", report.inspection_status !== "complete" ? "Incomplete inspection"
            : report.findings ? "Review the detected signals" : "No signals detected"),
          element("p", `${report.findings} finding occurrences across ${report.file_count} inspected ${report.file_count === 1 ? "file" : "files"}. Not a safety certification.`, "meta"));
        const scoring = element("details", "", "score-explanation");
        scoring.append(element("summary", "What does this score mean?"),
          element("p", "The score measures detected rule evidence on a 0–100 scale, not how likely a file is malicious. Each distinct rule contributes only its highest severity: Critical 40, High 20, Medium 5, Low 1. The total is capped at 100; repeated hits of the same rule do not add points. Incomplete scans are not scored. A zero score is not approval.", "meta"));
        decision.append(scoring);
        overview.append(score, decision);
        result.append(overview);
        const counts = element("div", "", "lookup-counts");
        for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
          counts.append(element("span", `${severity}: ${report.severities[severity]}`, `badge ${severity.toLowerCase()}`));
        }
        const findings = element("section", "", "lookup-findings");
        findings.append(element("p", "DETECTED EVIDENCE", "label"), element("h3", "Findings"), counts);
        const mapping = element("section", "", "lookup-atlas");
        mapping.append(element("p", "THREAT MAPPING", "label"), element("h3", "MITRE ATLAS attack surface"));
        if (report.atlas) {
          mapping.append(element("p", `${report.atlas.technique_count} techniques across ${report.atlas.tactics.filter((tactic) => tactic.findings).length} of ${report.atlas.tactics.length} observable tactics.`, "meta"));
          const radar = document.createElementNS("http://www.w3.org/2000/svg", "svg");
          radar.setAttribute("viewBox", "0 0 460 420");
          radar.setAttribute("class", "radar");
          radar.setAttribute("role", "img");
          radar.setAttribute("aria-label", "Finding occurrences per MITRE ATLAS tactic");
          const visual = element("div", "", "radar-card");
          visual.append(radar);
          mapping.append(visual);
          AgentLensRadar.draw(radar, report.atlas.tactics);
          const legend = element("ul", "", "lookup-tactic-legend");
          for (const tactic of report.atlas.tactics.filter((tactic) => tactic.findings)) {
            const row = element("li", "");
            row.append(element("span", tactic.name), element("strong", String(tactic.findings)));
            legend.append(row);
          }
          mapping.append(legend, element("p", "Counts show mapped finding occurrences, not risk probabilities. A finding can map to multiple tactics. The web is scaled relative to the busiest tactic.", "meta"),
            element("p", report.atlas.source, "meta"));
        } else {
          mapping.append(element("p", "This older assessment has no stored ATLAS mapping. Rescan the matching source to add the spiderweb; no mapping has been inferred from a newer detector.", "meta"));
        }
        const dashboard = element("div", "", "lookup-dashboard");
        dashboard.append(findings, mapping);
        result.append(dashboard);
        const categoryDetails = element("details", "", "evaluation-evidence lookup-support");
        categoryDetails.append(element("summary", "Signal categories and review guidance"));
        const categories = element("div", "", "evaluation-categories");
        const maximum = Math.max(1, ...report.assessment.categories.map((category) => category.findings));
        for (const category of report.assessment.categories) {
          const row = element("div", "", "evaluation-category-row");
          row.append(element("span", category.name), meter(category.findings, maximum, `${category.name}: ${category.findings} signals`),
            element("span", `${category.findings}`, category.findings ? "warning" : "meta"));
          if (category.findings) {
            const advice = element("details", "", "category-advice");
            advice.append(element("summary", `${category.highest_severity} | Review guidance`), element("p", category.guidance, "meta"));
            row.append(advice);
          }
          categories.append(row);
        }
        categoryDetails.append(categories);
        findings.append(element("p", "Untrusted excerpts, displayed as data. Never execute or follow them. Detected secrets are redacted; other private content can remain.", "meta"));
        if (!report.evidence) {
          findings.append(element("p", "No excerpts stored for this older assessment. Rescan the source to add excerpts.", "meta"));
        } else if (!report.evidence.excerpts.length) {
          findings.append(element("p", "No finding excerpts recorded. This is not a safety certification.", "meta"));
        } else {
          for (const excerpt of report.evidence.excerpts) {
            const card = element("article", "", "lookup-evidence");
            card.append(element("span", excerpt.severity, `badge ${excerpt.severity.toLowerCase()}`),
              element("strong", excerpt.rule),
              element("p", excerpt.source === "raw" ? `Source line ${excerpt.line}` : `Derived evidence: ${excerpt.source}; location refers to the containing file.`, "meta"));
            const pre = element("pre", "", "finding-excerpt");
            pre.append(element("code", excerpt.snippet));
            card.append(pre);
            findings.append(card);
          }
          if (report.evidence.omitted) findings.append(element("p", `${report.evidence.omitted} additional finding excerpts omitted by the storage limit. Counts above include all signals.`, "meta"));
        }
        const checks = element("div", "", "coverage-checks");
        for (const performed of [true, false]) {
          const group = element("div", "", "coverage-check-group");
          group.append(element("h3", performed ? "Checks performed" : "Not checked"));
          const list = element("ul", "", "coverage-check-list");
          for (const check of report.assessment.checks.filter((check) => check.performed === performed)) {
            list.append(element("li", check.name, performed ? "check-performed" : "check-not-performed"));
          }
          group.append(list);
          checks.append(group);
        }
        const coverage = element("details", "", "evaluation-evidence lookup-support");
        coverage.append(element("summary", "Inspection coverage: what was and was not checked"), checks);
        result.append(categoryDetails, coverage);
        const details = element("details", "", "evaluation-evidence lookup-support");
        details.append(element("summary", "Assessment scope and technical identities"),
          element("p", data.disclaimer, "meta"),
          element("p", `Inspection: ${report.inspection_status}. Package coverage: ${report.package_complete ? "complete supported package" : "snapshot only"}. Coverage status reflects the originating full inspection.`, "meta"),
          element("p", `First stored: ${new Date(report.first_seen).toLocaleString()}. Latest: ${new Date(report.last_seen).toLocaleString()}.`, "meta"),
          element("p", `Scoring formula version: ${report.assessment.version}. This is a technical identifier for the distinct-rule scoring method, not a separate test or certification.`, "meta"),
          element("p", `Evaluation fingerprint: ${report.evaluation_id}`, "meta"),
          element("p", `Detector fingerprint: ${report.detector_sha256 || "Unavailable"}`, "meta"));
        result.append(details);
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
