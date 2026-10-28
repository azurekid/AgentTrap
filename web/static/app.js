"use strict";
const $ = (id) => document.getElementById(id);
let mode = "upload";
let selected = [];
let report = null;
let busy = false;
let discover = false;
let sourceIndex = new Map();
const OWASP_URL = "https://genai.owasp.org/initiatives/#agentic-security-initiative";
let owaspRisks = new Map();

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}
function syncToken() {
  const on = mode === "repo" && $("private-repo").checked;
  $("token-field").hidden = !on;
  $("repo-token").disabled = !on;
  if (!on) $("repo-token").value = "";
}
function changeMode(next) {
  if (busy) return;
  mode = next;
  for (const [name, id] of [["upload", "upload-tab"], ["repo", "repo-tab"]]) {
    const active = name === next;
    $(id).classList.toggle("active", active);
    $(id).setAttribute("aria-selected", String(active));
    $(id).tabIndex = active ? 0 : -1;
    $(`${name}-panel`).hidden = !active;
  }
  $("repository").disabled = next !== "repo";
  $("private-repo").disabled = next !== "repo";
  syncToken();
  $("error").hidden = true;
}
const scannerPage = Boolean($("scan-form"));
const reportPage = Boolean($("findings"));
const REPORT_KEY = "skillvenom:report";
if ($("uniqueness-status")) {
  fetch("/api/statistics/unique", { headers: { Accept: "application/json" } })
    .then((response) => {
      if (!response.ok) throw new Error("Uniqueness unavailable");
      return response.json();
    })
    .then((data) => {
      for (const [id, key] of [["unique-skills", "skill_snapshots"], ["unique-complete", "complete_skill_versions"],
        ["unique-mcp", "mcp_snapshots"], ["unique-findings", "findings"]]) {
        const value = data.counts[key];
        if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid uniqueness count");
        $(id).textContent = value.toLocaleString();
      }
      $("uniqueness-status").textContent = data.since
        ? `Records since ${new Date(data.since).toLocaleDateString()}. Snapshot ${new Date(data.as_of).toLocaleString()}. ${data.consistency}`
        : "No content fingerprints have been recorded yet.";
    })
    .catch(() => {
      $("uniqueness-status").textContent = "Uniqueness counters are unavailable. Scan results are still available.";
    });
}
if ($("methodology-version")) {
  fetch("/api/methodology", { headers: { Accept: "application/json" } })
    .then((response) => {
      if (!response.ok) throw new Error("Methodology unavailable");
      return response.json();
    })
    .then((data) => {
      $("methodology-version").textContent = `${data.version} | Detector SHA256: ${data.detector_sha256}`;
    })
    .catch(() => {
      $("methodology-version").textContent = "Current detector identity is unavailable. Try again later.";
    });
}
if (scannerPage) $("private-repo").addEventListener("change", syncToken);
if (scannerPage) {
  $("upload-tab").addEventListener("click", () => changeMode("upload"));
  $("repo-tab").addEventListener("click", () => changeMode("repo"));
  document.querySelector(".tabs").addEventListener("keydown", (event) => {
    if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      changeMode(mode === "upload" ? "repo" : "upload");
      $(mode === "upload" ? "upload-tab" : "repo-tab").focus();
    }
  });
  if (new URLSearchParams(location.search).get("mode") === "repo") changeMode("repo");
}

function setScanning(on) {
  document.body.classList.toggle("scanning", on);
  $("console").classList.toggle("scanning", on);
  $("console-state").textContent = on ? "Inspecting…" : "Ready";
}
function showError(message) {
  $("error").textContent = message;
  $("error").hidden = false;
}
function setFiles(files, folder = false) {
  if (busy) return;
  const incoming = Array.from(files);
  discover = folder;
  if (folder) {
    // Let server discovery be authoritative; folder upload accepts supported text candidates.
    selected = incoming.filter((file) => /\.(md|mdc|json|toml|ya?ml)$/i.test(file.name)
      || /^\.(cursorrules|windsurfrules|clinerules)$/.test(file.name)
      || /\/\.(cursor|cline|clinerules)\/(?:rules\/)?[^/]+$/.test(file.webkitRelativePath)
      || /\/(skills\/[^/]+|\.claude\/hooks)\/.+\.(sh|bash|zsh|py|js|mjs|cjs|ts|ps1|rb)$/i.test(file.webkitRelativePath)
      || /\/\.claude\/hooks\/[^/]+$/.test(file.webkitRelativePath));
  } else {
    selected = incoming;
  }
  $("error").hidden = true;
  renderFiles();
}
function renderFiles() {
  $("file-list").replaceChildren();
  for (const [index, file] of selected.entries()) {
    const item = node("li", "", file.webkitRelativePath || file.name);
    item.append(node("span", "", `${(file.size / 1024).toFixed(1)} KiB`));
    const remove = node("button", "remove-file", "×");
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${file.name}`);
    remove.disabled = busy;
    remove.addEventListener("click", () => {
      selected.splice(index, 1);
      renderFiles();
    });
    item.append(remove);
    $("file-list").append(item);
  }
}
if (scannerPage) {
  $("files").addEventListener("change", (event) => setFiles(event.target.files));
  $("folder").addEventListener("change", (event) => setFiles(event.target.files, true));
  for (const name of ["dragover", "dragleave", "drop"]) {
    $("dropzone").addEventListener(name, (event) => {
      event.preventDefault();
      $("dropzone").classList.toggle("drag-over", name === "dragover");
      if (name === "drop") setFiles(event.dataTransfer.files);
    });
  }
}

const SVG = "http://www.w3.org/2000/svg";
let techniqueIndex = new Map();
function svg(tag, attrs = {}, text) {
  const element = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, String(value));
  if (text !== undefined) element.textContent = text;
  return element;
}
function externalLink(href, text, className = "") {
  const link = node("a", className, text);
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener";
  return link;
}
function techniqueName(tech) {
  return tech.parent ? `${tech.parent}: ${tech.name}` : tech.name;
}
const SHORT = { "command-and-control": ["Command &", "Control"], "credential-access": ["Credential", "Access"], "defense-evasion": ["Defense", "Evasion"], "initial-access": ["Initial", "Access"] };

function drawRadar(tactics) {
  const radar = $("atlas-radar");
  radar.replaceChildren(radar.querySelector("title"));
  const cx = 230, cy = 210, radius = 140, count = tactics.length;
  const peak = Math.max(1, ...tactics.map((t) => t.findings));
  const at = (index, scale) => {
    const angle = -Math.PI / 2 + (index / count) * Math.PI * 2;
    return [cx + Math.cos(angle) * radius * scale, cy + Math.sin(angle) * radius * scale];
  };
  const web = svg("g", { class: "radar-web" });
  for (const ring of [0.25, 0.5, 0.75, 1]) {
    web.append(svg("polygon", { points: tactics.map((_, i) => at(i, ring).join(",")).join(" "), class: ring === 1 ? "ring outer" : "ring" }));
  }
  tactics.forEach((tactic, i) => {
    const [x, y] = at(i, 1);
    web.append(svg("line", { x1: cx, y1: cy, x2: x, y2: y, class: `spoke${tactic.findings ? " hot" : ""}`, "data-key": tactic.key }));
  });
  radar.append(web);
  // sqrt keeps small counts visible next to one dominant tactic.
  const values = tactics.map((t) => (t.findings ? 0.14 + 0.86 * Math.sqrt(t.findings / peak) : 0));
  const shape = svg("g", { class: "radar-shape" });
  shape.append(svg("polygon", { points: values.map((v, i) => at(i, v).join(",")).join(" "), class: "area" }));
  tactics.forEach((tactic, i) => {
    if (!tactic.findings) return;
    const [x, y] = at(i, values[i]);
    shape.append(svg("circle", { cx: x, cy: y, r: 9, class: "halo", "data-key": tactic.key }));
    shape.append(svg("circle", { cx: x, cy: y, r: 4, class: "node", "data-key": tactic.key }));
  });
  radar.append(shape);
  tactics.forEach((tactic, i) => {
    const [x, y] = at(i, 1.17);
    const anchor = Math.abs(x - cx) < 12 ? "middle" : x > cx ? "start" : "end";
    const lines = SHORT[tactic.key] || [tactic.name];
    const label = svg("text", { x, y: y - (lines.length - 1) * 7, "text-anchor": anchor, class: `axis-label${tactic.findings ? " hot" : ""}`, "data-key": tactic.key });
    lines.forEach((line, n) => label.append(svg("tspan", { x, dy: n ? 15 : 0 }, line)));
    label.append(svg("tspan", { x, dy: 15, class: "axis-count" }, tactic.findings ? `${tactic.findings} finding${tactic.findings === 1 ? "" : "s"}` : "-"));
    radar.append(label);
  });
  radar.classList.remove("grow");
  requestAnimationFrame(() => requestAnimationFrame(() => radar.classList.add("grow")));
}

function highlight(key, on) {
  for (const element of document.querySelectorAll(`[data-key="${key}"]`)) element.classList.toggle("focus", on);
}

function renderAtlas(atlas) {
  techniqueIndex = new Map(atlas.techniques.map((tech) => [tech.id, tech]));
  if (atlas.owasp_asi?.risks) owaspRisks = new Map(atlas.owasp_asi.risks.map((r) => [r.id, r.name]));
  const hit = atlas.tactics.filter((t) => t.findings);
  $("atlas-version").textContent = atlas.source;
  $("atlas-summary").textContent = atlas.techniques.length
    ? `${atlas.techniques.length} technique${atlas.techniques.length === 1 ? "" : "s"} across ${hit.length} of ${atlas.tactics.length} observable tactics.`
    : "No findings map to ATLAS techniques in this inspection.";
  drawRadar(atlas.tactics);

  $("atlas-tactics").replaceChildren();
  const peak = Math.max(1, ...atlas.tactics.map((t) => t.findings));
  for (const tactic of atlas.tactics) {
    const item = node("li", tactic.findings ? "hot" : "");
    item.dataset.key = tactic.key;
    const link = externalLink(`https://atlas.mitre.org/tactics/${tactic.id}`, tactic.name);
    const meter = node("span", "meter");
    const fill = node("i");
    meter.append(fill);
    item.append(node("span", "tactic-id", tactic.id.replace("AML.", "")), link, meter, node("strong", "", String(tactic.findings)));
    item.addEventListener("mouseenter", () => highlight(tactic.key, true));
    item.addEventListener("mouseleave", () => highlight(tactic.key, false));
    $("atlas-tactics").append(item);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${Math.round((tactic.findings / peak) * 100)}%`; }));
  }

  $("atlas-details").open = false;
  $("atlas-technique-count").textContent = atlas.techniques.length ? String(atlas.techniques.length) : "";
  $("atlas-techniques").replaceChildren();
  for (const tech of atlas.techniques) {
    const card = node("article", "technique");
    const head = node("div", "technique-head");
    head.append(externalLink(tech.url, tech.id, "technique-id"), node("span", "technique-count", `${tech.findings} finding${tech.findings === 1 ? "" : "s"}`));
    card.append(head, node("h5", "", techniqueName(tech)));
    const tags = node("div", "technique-tags");
    for (const key of tech.tactics) {
      const tactic = atlas.tactics.find((t) => t.key === key);
      tags.append(node("span", "tag", tactic ? tactic.name : key));
    }
    card.append(tags);
    const rules = node("p", "technique-rules", `Rules: ${tech.rules.join(", ")}`);
    card.append(rules);
    const block = node("div", "mitigations");
    block.append(node("span", "mitigations-label", "Mitigations"));
    if (tech.mitigations.length) {
      const list = node("ul");
      for (const mitigation of tech.mitigations) {
        const item = node("li");
        item.append(externalLink(mitigation.url, mitigation.id, "mitigation-id"), node("span", "", mitigation.name));
        list.append(item);
      }
      block.append(list);
    }
    if (tech.guidance) {
      const guidance = node("p", "guidance");
      guidance.append(node("b", "", "AgentLens guidance: "), tech.guidance);
      block.append(guidance);
    }
    card.append(block);
    $("atlas-techniques").append(card);
  }
}

function renderSnapshotReview() {
  const artifacts = report.artifacts || [];
  $("snapshot-review").hidden = !artifacts.length;
  $("snapshot-cards").replaceChildren();
  $("fingerprint-status").hidden = true;
  const snapshots = artifacts.map((artifact) => {
    const paths = new Set(artifact.files.map((file) => artifact.kind === "skill_snapshot"
      ? (artifact.root === "." ? file.path : `${artifact.root}/${file.path}`) : artifact.root));
    const files = report.files.filter((file) => paths.has(file.path));
    const hits = files.flatMap((file) => file.findings);
    return { artifact, files, critical: hits.filter((hit) => hit.severity === "CRITICAL").length,
      high: hits.filter((hit) => hit.severity === "HIGH").length };
  }).sort((a, b) => b.critical - a.critical || b.high - a.high || a.artifact.root.localeCompare(b.artifact.root));
  const affected = snapshots.filter((item) => item.critical || item.high).length;
  $("snapshot-review-summary").textContent = `${affected} of ${snapshots.length} snapshots have HIGH or CRITICAL signals in this view. Counts are finding occurrences in ${report.view_scope ? "the selected file only" : "this report"}, not unique skills across the platform.${report.status !== "complete" ? " This inspection is incomplete; absence of signals cannot establish a clean result." : ""}`;
  const query = $("snapshot-search").value.trim().toLowerCase();
  const filter = $("snapshot-filter").value;
  for (const { artifact, files, critical, high } of snapshots) {
    if (query && !`${artifact.root} ${artifact.content_id} ${artifact.evaluation_id}`.toLowerCase().includes(query)) continue;
    if (filter === "review" && !critical && !high) continue;
    if (filter === "seen" && artifact.seen_before !== true) continue;
    if (filter === "new" && artifact.seen_before !== false) continue;
    const card = node("details", `card snapshot-card${critical || high ? " needs-review" : ""}`);
    const kind = { skill_snapshot: "Skill snapshot", mcp_snapshot: "MCP definition snapshot", agent_file: "Agent file" }[artifact.kind] || "Snapshot";
    const heading = node("summary", "snapshot-row");
    const name = node("span", "snapshot-name", `${kind}: ${artifact.root}`);
    heading.append(name, node("span", critical || high ? "warning" : "meta", `${critical} CRITICAL / ${high} HIGH`),
      node("span", "meta", artifact.seen_before === true ? "Seen before" : artifact.seen_before === false ? "First recorded" : "Sighting unknown"));
    if (files.length === 1 && !report.view_scope) {
      const link = node("a", "", "Open file report");
      link.href = `/report?file=${encodeURIComponent(files[0].path)}`;
      heading.append(link);
    }
    card.append(heading, node("p", critical || high ? "warning" : "meta", critical || high
        ? `Review required: ${critical} CRITICAL, ${high} HIGH signal(s)`
        : "No HIGH or CRITICAL signals in inspected content. This is not approval."),
      node("p", "meta", artifact.scope));
    card.append(node("p", artifact.seen_before === true ? "warning" : "meta",
      artifact.seen_before === true ? "Seen before: this exact content fingerprint already exists in the central registry."
        : artifact.seen_before === false ? "First recorded: this content fingerprint was new when this scan was registered."
          : "Prior sightings unavailable for this report."));
    const fingerprints = node("details", "snapshot-identities");
    fingerprints.append(node("summary", "", `SHA256 ${artifact.content_id.slice(0, 16)}... | Fingerprint details`));
    for (const [label, value] of [["Content fingerprint (SHA256)", artifact.content_id], ["Evaluation fingerprint (SHA256)", artifact.evaluation_id]]) {
      const field = node("div", "snapshot-fingerprint");
      const input = node("input");
      input.type = "text";
      input.readOnly = true;
      input.value = value;
      input.id = `snapshot-${$("snapshot-cards").childElementCount}-${label.startsWith("Content") ? "content" : "evaluation"}`;
      input.setAttribute("aria-label", `${label}: ${artifact.root}`);
      const copy = node("button", "btn btn-ghost btn-small", "Copy");
      copy.type = "button";
      copy.setAttribute("aria-label", `Copy ${label}: ${artifact.root}`);
      copy.addEventListener("click", async () => {
        const status = $("fingerprint-status");
        status.hidden = false;
        try {
          await navigator.clipboard.writeText(value);
          status.textContent = `${label} copied.`;
        } catch {
          input.focus();
          input.select();
          status.textContent = "Clipboard unavailable. The full fingerprint is selected; copy it manually.";
        }
      });
      const caption = node("label", "meta", label);
      caption.htmlFor = input.id;
      field.append(caption, input, copy);
      fingerprints.append(field);
    }
    card.append(fingerprints);
    for (const note of artifact.coverage_notes) card.append(node("p", "warning", note));
    const fileList = node("ul", "snapshot-file-links");
    for (const file of files) {
      const item = node("li");
      const link = node("a", "", `${file.path} (${file.findings.length} signals)`);
      link.href = `/report?file=${encodeURIComponent(file.path)}`;
      item.append(link);
      fileList.append(item);
    }
    card.append(fileList);
    $("snapshot-cards").append(card);
  }
  if (artifacts.length && !$("snapshot-cards").childElementCount) {
    $("snapshot-cards").append(node("p", "meta", "No snapshots match these filters."));
  }
}

function renderEvaluation() {
  const evaluation = report.evaluation;
  $("evaluation").hidden = !evaluation;
  $("finding-category").replaceChildren(node("option", "", "All categories"));
  $("finding-category").firstChild.value = "ALL";
  if (!evaluation) {
    const categories = new Map(report.files.flatMap((file) => file.findings)
      .filter((hit) => hit.category).map((hit) => [hit.category, report.category_names?.[hit.category] || hit.category]));
    for (const [id, name] of categories) {
      const option = node("option", "", name);
      option.value = id;
      $("finding-category").append(option);
    }
    return;
  }
  const complete = report.status === "complete";
  const status = !complete ? "Incomplete evaluation"
    : evaluation.decision === "review_required" ? "Manual review required" : "No rule signals detected";
  const score = evaluation.score === null ? "Not scored" : `${evaluation.score}/100`;
  $("evaluation-summary").replaceChildren(
    node("h3", "", `${status} | ${score}`),
    node("p", "meta", "Signal risk score: higher means more distinct rule evidence, not a probability of malware. A score of zero is not approval. Duplicate hits of the same rule do not increase the score."),
    node("p", "meta", `Highest observed severity: ${evaluation.highest_severity || "none"}. Method: ${evaluation.version}.`),
  );
  $("evaluation-categories").replaceChildren();
  for (const category of evaluation.categories) {
    const option = node("option", "", category.name);
    option.value = category.id;
    $("finding-category").append(option);
    const card = node("article", "card evaluation-category");
    card.append(node("h3", "", category.name));
    card.append(node("p", category.findings ? "warning" : "meta",
      category.findings ? `${category.findings} signals | ${category.highest_severity}` : "No signals in inspected files"));
    card.append(node("p", "meta", category.guidance));
    $("evaluation-categories").append(card);
  }
  $("evaluation-checks").replaceChildren();
  for (const check of evaluation.checks) {
    $("evaluation-checks").append(node("p", "meta", `${check.performed ? "Performed" : "Not performed"}: ${check.name}`));
  }
  const provenance = report.provenance;
  $("evaluation-provenance").replaceChildren();
  if (provenance) {
    $("evaluation-provenance").append(
      node("p", "meta", `Detector SHA256: ${provenance.detector_sha256}`),
      node("p", "meta", `Manifest SHA256: ${provenance.manifest_sha256}`),
      node("p", "meta", provenance.hash_scope),
    );
    const list = node("ul", "fingerprint-list");
    for (const file of provenance.files) {
      const item = node("li");
      item.append(node("strong", "", file.path), node("code", "", `${file.bytes} bytes | SHA256 ${file.sha256}`));
      list.append(item);
    }
    $("evaluation-provenance").append(list);
  }
  for (const artifact of report.artifacts || []) {
    const item = node("details", "artifact-evidence");
    item.append(node("summary", "", `${artifact.kind}: ${artifact.root}`),
      node("p", "meta", artifact.scope),
      node("p", "meta", `Content ID: ${artifact.content_id}`),
      node("p", "meta", `Evaluation ID: ${artifact.evaluation_id}`));
    for (const note of artifact.coverage_notes) item.append(node("p", "warning", note));
    $("evaluation-provenance").append(item);
  }
}
function renderHeatmap() {
  const categories = new Map((report.evaluation?.categories || []).map((category) => [category.id, category.name]));
  for (const file of report.files) for (const hit of file.findings) {
    if (!categories.has(hit.category)) categories.set(hit.category || "uncategorized", report.category_names?.[hit.category] || hit.category || "Uncategorized");
  }
  const table = node("table", "heatmap-table");
  const head = node("tr");
  head.append(node("th", "", "Category"));
  for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) head.append(node("th", "", severity));
  const thead = node("thead");
  thead.append(head);
  table.append(thead);
  const body = node("tbody");
  for (const [id, name] of categories) {
    const row = node("tr");
    const title = node("th", "", name);
    title.scope = "row";
    row.append(title);
    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
      const count = report.files.flatMap((file) => file.findings).filter((hit) => (hit.category || "uncategorized") === id && hit.severity === severity).length;
      const cell = node("td");
      const button = node("button", `heatmap-cell${count ? ` heat-${severity.toLowerCase()}` : ""}`, String(count));
      button.type = "button";
      button.disabled = !count;
      button.setAttribute("aria-label", `${name}, ${severity}: ${count} signals`);
      button.addEventListener("click", () => {
        $("severity").value = severity;
        $("finding-category").value = Array.from($("finding-category").options).some((option) => option.value === id) ? id : "ALL";
        $("finding-search").value = "";
        renderFindings();
        $("findings").scrollIntoView({ block: "start" });
      });
      cell.append(button);
      row.append(cell);
    }
    body.append(row);
  }
  table.append(body);
  $("heatmap-grid").replaceChildren(table);
}
function renderResults() {
  $("finding-heatmap").before(document.querySelector(".atlas"));
  renderSnapshotReview();
  const summary = report.summary;
  const incomplete = report.status === "partial" || report.status === "no_targets";
  const risky = summary.severities.CRITICAL || summary.severities.HIGH;
  const tone = risky ? "risky" : incomplete ? "warn" : "clean";
  const verdict = $("verdict");
  verdict.className = `verdict ${tone}`;
  const text = node("div");
  text.append(
    node("span", "verdict-label", report.status === "no_targets" ? "NO TARGET FILES" : summary.verdict),
    node("span", "verdict-sub", report.status === "no_targets"
      ? "No supported agent files found, this is not a clean bill of health."
      : `${report.status === "partial" ? "Partial scan · " : ""}${summary.findings} finding${summary.findings === 1 ? "" : "s"} across ${summary.files} file${summary.files === 1 ? "" : "s"}`),
  );
  verdict.replaceChildren(node("span", "verdict-icon", risky ? "!" : incomplete ? "?" : "✓"), text);

  const sev = summary.severities;
  const total = sev.CRITICAL + sev.HIGH + sev.MEDIUM + sev.LOW;
  const donut = $("donut");
  let cumulative = 0;
  const stops = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((key) => (cumulative += total ? (sev[key] / total) * 100 : 0));
  for (const name of ["--a", "--b", "--c", "--d"]) donut.style.setProperty(name, "0");
  $("donut-total").textContent = String(summary.findings);

  $("metrics").replaceChildren();
  const peak = Math.max(1, sev.CRITICAL, sev.HIGH, sev.MEDIUM, sev.LOW);
  const meters = [];
  for (const [label, severity] of [["CRITICAL", "critical"], ["HIGH", "high"], ["MEDIUM", "medium"], ["LOW", "low"]]) {
    const row = node("div", "metric");
    const meter = node("span", "meter");
    const fill = node("i", severity);
    meter.append(fill);
    meters.push([fill, sev[label] / peak]);
    row.append(node("span", "", label), meter, node("strong", "", String(sev[label])));
    $("metrics").append(row);
  }
  requestAnimationFrame(() => requestAnimationFrame(() => {
    for (const [fill, ratio] of meters) fill.style.width = `${Math.round(ratio * 100)}%`;
    ["--a", "--b", "--c", "--d"].forEach((name, index) => donut.style.setProperty(name, stops[index].toFixed(2)));
  }));
  $("report-notes").replaceChildren(
    node("p", "meta", `Source: ${report.source}`),
    node("p", "meta", `Inspected: ${new Date(report.created_at).toLocaleString()}`),
  );
  if (report.commit) $("report-notes").append(node("p", "meta", `Commit: ${report.commit}`));
  if (!report.view_scope && !report.skipped.length && report.archive.status !== "stored" && report.archive.status !== "failed") {
    $("report-notes").append(node("p", "", "All discovered files were inspected."));
  }
  if (report.archive.status === "stored") {
    $("report-notes").append(node("p", "warning", `${report.archive.files} high-risk file(s) retained in the private investigation archive for 30 days${report.view_scope ? " across the full inspection" : ""}.`));
  } else if (report.archive.status === "opted_out") {
    $("report-notes").append(node("p", "meta", "Investigation retention opted out: no files were retained."));
  } else if (report.archive.status === "failed") {
    $("report-notes").append(node("p", "warning", report.archive.message));
  }
  for (const path of report.skipped) $("report-notes").append(node("p", "warning", `Not inspected: ${path}`));
  if (report.statistics?.status === "failed") {
    $("report-notes").append(node("p", "warning", report.statistics.message));
  }
  if (report.uniqueness) {
    $("report-notes").append(node("p", report.uniqueness.status === "failed" ? "warning" : "meta",
      report.uniqueness.status === "failed" ? report.uniqueness.message
        : `Unique-content tracking: ${report.uniqueness.status.replaceAll("_", " ")}.`));
  }
  if (report.inventory) {
    $("report-notes").append(node("p", "meta", `${report.inventory.skill_snapshots} skill snapshots, `
      + `${report.inventory.complete_skill_packages} complete supported packages, ${report.inventory.mcp_snapshots} MCP snapshots, `
      + `${report.inventory.agent_files} other agent files. Files are not counted as skills.`));
  }
  $("disclaimer").textContent = report.disclaimer;
  $("finding-count").textContent = `${summary.findings} signals across ${summary.files} files`;
  $("severity").value = "ALL";
  $("finding-search").value = "";
  renderEvaluation();
  renderHeatmap();
  renderAtlas(report.atlas);
  renderFindings();
  $("results").hidden = false;
}
function renderFindings() {
  $("findings").replaceChildren();
  const filter = $("severity").value;
  const category = $("finding-category").value;
  const query = $("finding-search").value.trim().toLowerCase();
  let visible = 0;
  let visibleFindings = 0;
  const clean = report.files.filter((file) => !file.findings.length).length;
  for (const file of report.files) {
    const findings = file.findings.filter((finding) =>
      (filter === "ALL" || finding.severity === filter)
      && (category === "ALL" || finding.category === category)
      && (!query || `${file.path} ${finding.rule} ${finding.message} ${finding.snippet}`.toLowerCase().includes(query)));
    if (!findings.length) continue;
    visible++;
    visibleFindings += findings.length;
    const details = node("details", "file-result");
    details.dataset.path = file.path;
    details.open = Boolean(report.view_scope);
    const summary = node("summary", "", file.path);
    summary.append(node("span", "", `${findings.length} finding(s)`));
    if (!report.view_scope) summary.addEventListener("click", (event) => {
      event.preventDefault();
      location.assign(`/report?file=${encodeURIComponent(file.path)}`);
    });
    details.append(summary);
    const dashboard = node("a", "btn btn-ghost btn-small", "Open file report");
    dashboard.href = `/report?file=${encodeURIComponent(file.path)}`;
    details.append(dashboard);
    for (const finding of findings) {
      const article = node("article", `finding sev-${finding.severity.toLowerCase()}`);
      const heading = node("div", "finding-heading");
      heading.append(node("span", `badge ${finding.severity.toLowerCase()}`, finding.severity),
        node("strong", "", finding.rule), node("span", "line-number",
          finding.json_pointer ? `JSON ${finding.json_pointer}` : `LINE ${finding.line}`));
      article.append(heading, node("p", "", finding.message), node("pre", "", finding.snippet));
      if (finding.encoding_chain) {
        article.append(node("p", "meta", `Decoded evidence: ${finding.encoding_chain.join(" -> ")}; decoded line ${finding.decoded_line}. The location above identifies the containing encoded text, not an invented decoded source line.`));
      }
      if (finding.rule.startsWith("SECRET-")) {
        article.append(node("p", "", "If real: revoke and rotate this credential, remove it from instructions and history, and review access logs. Detection does not verify whether a credential is active."));
      }
      if (finding.atlas?.length) {
        const chips = node("div", "atlas-chips");
        chips.append(node("span", "atlas-chips-label", "ATLAS"));
        for (const id of finding.atlas) {
          const tech = techniqueIndex.get(id);
          chips.append(externalLink(`https://atlas.mitre.org/techniques/${id}`, `${id} · ${tech ? techniqueName(tech) : ""}`, "atlas-chip"));
        }
        article.append(chips);
      }
      if (finding.owasp?.length) {
        const chips = node("div", "atlas-chips owasp-chips");
        chips.append(node("span", "atlas-chips-label", "OWASP"));
        for (const id of finding.owasp) {
          chips.append(externalLink(OWASP_URL, `${id} · ${owaspRisks.get(id) || ""}`, "atlas-chip owasp-chip"));
        }
        article.append(chips);
      }
      if (finding.ref) {
        const refs = node("div", "refs");
        refs.append(node("span", "refs-label", "Research"));
        const list = node("ul");
        for (const id of finding.ref.split(",").map((value) => value.trim()).filter((value) => /^\d+$/.test(value))) {
          const source = sourceIndex.get(id);
          const item = node("li");
          // Open the cited article itself; fall back to the research page when a source has no URL.
          const link = externalLink(source?.urls[0] || `/sources#source-${id}`, source ? source.title : `Source ${id}`);
          link.prepend(node("span", "ref-num", id));
          if (source?.author) link.title = `${source.author}${source.date ? ` · ${source.date}` : ""}`;
          item.append(link);
          list.append(item);
        }
        refs.append(list);
        article.append(refs);
      }
      const fp = node("button", "fp-link", "Report false positive");
      fp.type = "button";
      fp.addEventListener("click", () => { allFindings(); openFalsePositive(findingKeys.get(finding)); });
      article.append(fp);
      details.append(article);
    }
    $("findings").append(details);
  }
  if (!visible) {
    const message = report.files.length && clean === report.files.length
      ? "No security signals detected by the current rules. Manual review is still recommended."
      : "No findings match these filters.";
    $("findings").append(node("div", "empty-state", message));
  }
  if (clean) $("findings").append(node("p", "clean-note", `${clean} scanned ${clean === 1 ? "file" : "files"} with no findings ${clean === 1 ? "is" : "are"} not listed.`));
  for (const file of report.files) {
    if (file.decoding) {
      const info = node("details", "card evaluation-evidence");
      info.append(node("summary", "", `${file.path}: encoded-text inspection (${file.decoding.status}, ${file.decoding.payloads} payloads)`),
        node("p", "meta", file.decoding.scope));
      for (const note of file.decoding.notes) info.append(node("p", "warning", note));
      $("findings").append(info);
    }
    if (!file.mcp || file.mcp.status === "not_applicable") continue;
    const info = node("details", "card evaluation-evidence");
    info.append(node("summary", "", `${file.path}: structured MCP inspection (${file.mcp.status}, ${file.mcp.tools} tools)`));
    for (const observation of file.mcp.observations) {
      info.append(node("p", "meta", `${observation.pointer || ""} ${observation.message}`));
    }
    info.append(node("p", "meta", "Schema and sensitive-input observations are not vulnerability findings and do not increase the signal score."));
    $("findings").append(info);
  }
  $("finding-count").textContent = `${visibleFindings} of ${report.summary.findings} signals shown`;
}
const findingKeys = new WeakMap();
function allFindings() {
  return report.files.flatMap((file) => file.findings.map((f, i) => {
    findingKeys.set(f, `${file.path}\u0000${i}`);
    return { ...f, path: file.path, key: findingKeys.get(f) };
  }));
}
function openFalsePositive(selectedKey) {
  const list = $("fp-list");
  list.replaceChildren();
  for (const f of allFindings()) {
    const item = node("li");
    const label = node("label");
    const box = node("input");
    box.type = "checkbox";
    box.value = f.key;
    box.checked = f.key === selectedKey;
    label.append(box, node("span", `badge ${f.severity.toLowerCase()}`, f.severity), node("code", "", f.rule),
      node("span", "meta", f.json_pointer ? `${f.path} JSON ${f.json_pointer}` : `${f.path}:${f.line}`));
    item.append(label);
    list.append(item);
  }
  $("fp-comment").value = "";
  $("fp-snippets").checked = false;
  $("fp-status").hidden = true;
  $("fp-send").disabled = false;
  $("fp-dialog").showModal();
}
if (reportPage) {
  $("snapshot-search").addEventListener("input", renderSnapshotReview);
  $("snapshot-filter").addEventListener("change", renderSnapshotReview);
  $("fp-open").addEventListener("click", () => openFalsePositive());
  $("fp-cancel").addEventListener("click", () => $("fp-dialog").close());
  $("fp-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const keys = new Set(Array.from($("fp-list").querySelectorAll("input:checked"), (box) => box.value));
    const chosen = allFindings().filter((f) => keys.has(f.key)).slice(0, 50);
    const status = $("fp-status");
    status.hidden = false;
    if (!chosen.length) { status.textContent = "Select at least one finding."; return; }
    const withSnippets = $("fp-snippets").checked;
    $("fp-send").disabled = true;
    try {
      const response = await fetch("/api/feedback", {
        method: "POST", headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(20000),
        body: JSON.stringify({
          scan_id: report.id, source: String(report.source || "").slice(0, 300), commit: report.commit || null,
          comment: $("fp-comment").value.trim(),
          findings: chosen.map((f) => ({
            rule: f.rule, severity: f.severity, path: f.path.slice(0, 300), line: f.line,
            ...(f.json_pointer && { json_pointer: f.json_pointer.slice(0, 8192) }),
            ...(withSnippets && !f.rule.startsWith("SECRET-") && { snippet: String(f.snippet).slice(0, 300) }),
          })),
        }),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(response.status === 429 ? "Too many reports. Try again later." : typeof data.detail === "string" && response.status !== 422 ? data.detail : "The report could not be sent.");
      }
      status.textContent = "Thank you. Your report was received.";
      setTimeout(() => $("fp-dialog").close(), 1200);
    } catch (error) {
      status.textContent = error.message || "The report could not be sent.";
      $("fp-send").disabled = false;
    }
  });
  $("severity").addEventListener("change", renderFindings);
  $("finding-category").addEventListener("change", renderFindings);
  $("finding-search").addEventListener("input", renderFindings);

  fetch("/api/sources", { headers: { Accept: "application/json" } })
    .then((response) => (response.ok ? response.json() : null))
    .then((data) => {
      if (!data) return;
      sourceIndex = new Map(data.sections.flatMap((section) => section.sources.map((source) => [source.id, source])));
      if (report) renderFindings();
    })
    .catch(() => {});
  for (const [id, format] of [["download", "json"], ["download-sarif", "sarif"]]) {
    $(id).addEventListener("click", () => {
      $("export-status").hidden = true;
      try {
        const data = format === "sarif" ? buildSarif(report) : report;
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = node("a");
        link.href = url;
        link.download = `agentlens-${report.id}.${format}`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (error) {
        $("export-status").textContent = `Export failed: ${error.message || "Invalid report."}`;
        $("export-status").hidden = false;
      }
    });
  }
  let stored = null;
  try { stored = JSON.parse(sessionStorage.getItem(REPORT_KEY)); } catch { /* ignore */ }
  if (stored?.files && stored?.atlas) {
    const path = new URLSearchParams(location.search).get("file");
    const file = path ? stored.files.find((item) => item.path === path) : null;
    if (path && !file) {
      $("results").hidden = true;
      $("no-report").hidden = false;
      const back = node("a", "", "Open the full report");
      back.href = "/report";
      $("no-report").replaceChildren(document.createTextNode("This file is not part of the current browser-tab inspection. "), back);
    } else {
      report = path ? fileReport(stored, file) : stored;
      if (path) {
        $("results-title").textContent = "File report";
        document.title = `File report | AgentLens`;
        $("back-to-report").hidden = false;
        const context = $("file-context");
        context.hidden = false;
        context.append(node("p", "", path));
        const fingerprint = stored.provenance?.files.find((item) => item.path === path);
        if (fingerprint) context.append(node("p", "meta", `Inspected-text SHA256: ${fingerprint.sha256}`));
        context.append(node("p", "meta", "Findings and threat mapping below cover this file only. Snapshot fingerprints and completeness describe its containing package from the full inspection."));
      }
      renderResults();
    }
  } else {
    $("results").hidden = true;
    $("no-report").hidden = false;
  }
  function fileReport(full, file) {
    const scoped = structuredClone(full);
    scoped.files = [structuredClone(file)];
    scoped.artifacts = (scoped.artifacts || []).filter((artifact) => artifact.files.some((entry) =>
      (artifact.kind === "skill_snapshot" ? (artifact.root === "." ? entry.path : `${artifact.root}/${entry.path}`) : artifact.root) === file.path));
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const hit of file.findings) counts[hit.severity]++;
    scoped.summary = { files: 1, findings: file.findings.length, severities: counts,
      verdict: counts.CRITICAL || counts.HIGH ? "REVIEW REQUIRED" : "NO HIGH-RISK SIGNALS DETECTED" };
    scoped.inventory = null;
    scoped.category_names = Object.fromEntries((full.evaluation?.categories || []).map((category) => [category.id, category.name]));
    scoped.evaluation = null;
    const techniques = scoped.atlas.techniques.filter((tech) => file.findings.some((hit) => hit.atlas?.includes(tech.id)));
    for (const tech of techniques) {
      const hits = file.findings.filter((hit) => hit.atlas?.includes(tech.id));
      tech.findings = hits.length;
      tech.rules = [...new Set(hits.map((hit) => hit.rule))];
      if (hits.every((hit) => hit.atlas_mapping)) {
        tech.tactics = [...new Set(hits.flatMap((hit) => hit.atlas_mapping)
          .filter((pair) => pair.technique === tech.id).map((pair) => pair.tactic))];
      }
    }
    scoped.atlas.techniques = techniques;
    for (const tactic of scoped.atlas.tactics) {
      const ids = new Set(techniques.filter((tech) => tech.tactics.includes(tactic.key)).map((tech) => tech.id));
      tactic.findings = file.findings.filter((hit) => hit.atlas_mapping
        ? hit.atlas_mapping.some((pair) => pair.tactic === tactic.key)
        : hit.atlas?.some((id) => ids.has(id))).length;
    }
    for (const risk of scoped.atlas.owasp_asi?.risks || []) {
      risk.findings = file.findings.filter((hit) => hit.owasp?.includes(risk.id)).length;
    }
    if (scoped.atlas.owasp_asi) scoped.atlas.owasp_asi.risks = scoped.atlas.owasp_asi.risks.filter((risk) => risk.findings);
    scoped.view_scope = { kind: "file", path: file.path, snapshot_scope: "containing package from full inspection" };
    return scoped;
  }
}
if (scannerPage) {
  $("scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    $("error").hidden = true;
    let body;
    const headers = {};
    const workflows = mode === "repo" && $("workflows").checked;
    if (mode === "upload") {
      if (!selected.length) return showError("Select at least one file to inspect.");
      if (selected.length > 500 || selected.some((file) => file.size > 256 * 1024)
        || selected.reduce((total, file) => total + file.size, 0) > 5 * 1024 * 1024) {
        return showError("Select up to 500 files, at most 256 KiB each and 5 MiB combined.");
      }
      body = new FormData();
      body.append("include_workflows", String(workflows));
      body.append("discover", String(discover));
      for (const file of selected) body.append("files", file, file.webkitRelativePath || file.name);
    } else {
      const url = $("repository").value.trim();
      if (!url) return showError("Enter a repository URL.");
      const token = $("private-repo").checked ? $("repo-token").value.trim() : "";
      body = JSON.stringify({ url, include_workflows: workflows, ...(token && { token }) });
      headers["Content-Type"] = "application/json";
    }
    busy = true;
    setScanning(true);
    $("scan-button").disabled = true;
    $("scan-button").textContent = "Inspecting…";
    $("progress").hidden = false;
    for (const id of ["files", "folder", "repository", "private-repo", "repo-token", "workflows"]) $(id).disabled = true;
    renderFiles();
    try {
      const response = await fetch(`/api/scan/${mode === "upload" ? "files" : "repository"}`, { method: "POST", body, headers, signal: AbortSignal.timeout(120000) });
      if (!response.headers.get("content-type")?.includes("application/json")) throw new Error("The scan service returned an unexpected response. Try again later.");
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The request was rejected. Check your selected files.");
      report = data;
      document.dispatchEvent(new Event("skillvenom:scan-complete"));
      try {
        sessionStorage.setItem(REPORT_KEY, JSON.stringify(report));
      } catch {
        throw new Error("The report is too large to open on its own page. Narrow the scan and try again.");
      }
      location.assign("/report");
    } catch (error) {
      showError(error.name === "TimeoutError" ? "The request timed out. No complete result is available." : error.message || "Unable to reach the scanner.");
    } finally {
      busy = false;
      setScanning(false);
      $("scan-button").disabled = false;
      $("scan-button").replaceChildren(document.createTextNode("Run inspection "), node("span", "", "→"));
      $("progress").hidden = true;
      for (const id of ["files", "folder", "repository", "private-repo", "repo-token", "workflows"]) $(id).disabled = false;
      $("repository").disabled = mode !== "repo";
      $("private-repo").disabled = mode !== "repo";
      syncToken();
      renderFiles();
    }
  });
}

let sampleCatalog = null;
let sampleSeverity = "ALL";

function matchesCase(item, query, category, platform) {
  if (sampleSeverity !== "ALL" && item.severity !== sampleSeverity) return false;
  if (category !== "ALL" && item.category !== category) return false;
  if (platform !== "ALL" && !item.platforms.includes(platform)) return false;
  if (!query) return true;
  const hay = `${item.id} ${item.title} ${item.summary} ${item.source} ${item.rules.join(" ")} `
    + `${item.mitre_atlas.join(" ")} ${item.owasp_asi.join(" ")} ${item.platforms.join(" ")} `
    + item.findings.map((f) => `${f.rule} ${f.snippet}`).join(" ");
  return hay.toLowerCase().includes(query);
}

function sampleCard(item) {
  const card = node("details", `sample-case sev-${item.severity.toLowerCase()}`);
  const summary = node("summary");
  const top = node("div", "sample-case-top");
  top.append(node("span", "badge " + item.severity.toLowerCase(), item.severity),
    node("span", "sample-id", item.id), node("strong", "sample-title", item.title));
  const tags = node("div", "sample-tags");
  for (const platform of item.platforms) tags.append(node("span", "sample-tag", platform));
  summary.append(top, node("p", "sample-summary", item.summary), tags);
  card.append(summary);

  const body = node("div", "sample-case-body");
  if (item.findings.length) {
    body.append(node("p", "sample-h", "Detections"));
    const list = node("ul", "sample-findings");
    for (const f of item.findings) {
      const li = node("li");
      li.append(node("span", "badge " + f.severity.toLowerCase(), f.severity),
        node("code", "sample-rule", f.rule),
        node("span", "sample-loc", `${f.scan_as}:${f.line}`));
      li.append(node("pre", "", f.snippet));
      list.append(li);
    }
    body.append(list);
  }
  const chips = node("div", "sample-chips");
  for (const id of item.mitre_atlas) chips.append(externalLink(`https://atlas.mitre.org/techniques/${id}`, id, "atlas-chip"));
  for (const id of item.owasp_asi) chips.append(externalLink(sampleCatalog.owasp_url || OWASP_URL, `${id} · ${(sampleCatalog.owasp_names && sampleCatalog.owasp_names[id]) || ""}`, "atlas-chip owasp-chip"));
  if (chips.childNodes.length) body.append(chips);

  if (item.why) { body.append(node("p", "sample-h", "Why it works"), node("p", "sample-text", item.why)); }
  if (item.mitigations?.length) {
    body.append(node("p", "sample-h", "Mitigations"));
    const ul = node("ul", "sample-mitig");
    for (const m of item.mitigations) ul.append(node("li", "", m));
    body.append(ul);
  }
  const foot = node("div", "sample-foot");
  foot.append(node("span", "sample-source", item.source));
  if (item.url) foot.append(externalLink(item.url, "View in catalogue →", "sample-link"));
  body.append(foot);
  card.append(body);
  return card;
}

function renderSamples() {
  if (!sampleCatalog) return;
  const query = $("sample-search").value.trim().toLowerCase();
  const category = $("sample-category").value;
  const platform = $("sample-platform").value;
  const grid = $("sample-grid");
  grid.replaceChildren();
  const visible = sampleCatalog.cases.filter((item) => matchesCase(item, query, category, platform));
  const byCat = new Map();
  for (const item of visible) {
    if (!byCat.has(item.category)) byCat.set(item.category, []);
    byCat.get(item.category).push(item);
  }
  for (const cat of sampleCatalog.categories) {
    const items = byCat.get(cat.code);
    if (!items || !items.length) continue;
    const group = node("div", "sample-group");
    const head = node("div", "sample-group-head");
    head.append(node("span", "sample-cat-code", cat.code), node("h3", "", cat.title),
      node("span", "sample-cat-n", `${items.length}`));
    group.append(head, node("p", "sample-cat-desc", cat.description));
    const cards = node("div", "sample-cards");
    for (const item of items.sort((a, b) => a.id.localeCompare(b.id))) cards.append(sampleCard(item));
    group.append(cards);
    grid.append(group);
  }
  if (!visible.length) grid.append(node("p", "research-empty", "No use cases match these filters."));
  $("sample-count").textContent = `${visible.length} use case${visible.length === 1 ? "" : "s"}`;
}

function loadSamples() {
  if (sampleCatalog) return;
  sampleCatalog = { cases: [] };
  fetch("/api/samples", { headers: { Accept: "application/json" } })
    .then((response) => (response.ok ? response.json() : Promise.reject(new Error(String(response.status)))))
    .then((data) => {
      sampleCatalog = data;
      sampleCatalog.owasp_names = data.owasp_risks || {};
      const platforms = new Set(data.cases.flatMap((c) => c.platforms));
      const catSelect = $("sample-category");
      for (const cat of data.categories) {
        const opt = node("option", "", `${cat.code} · ${cat.title}`);
        opt.value = cat.code;
        catSelect.append(opt);
      }
      const platSelect = $("sample-platform");
      for (const p of (data.platforms || []).filter((p) => platforms.has(p.id))) {
        const opt = node("option", "", p.title);
        opt.value = p.id;
        platSelect.append(opt);
      }
      const stats = $("sample-stats");
      stats.replaceChildren();
      const pairs = [[data.cases.length, "use cases"], [data.rules.length, "detectors"],
        [data.categories.length, "categories"], [platforms.size, "platforms"]];
      for (const [value, label] of pairs) {
        const pill = node("span", "", label);
        pill.prepend(node("b", "", String(value)));
        stats.append(pill);
      }
      renderSamples();
    })
    .catch(() => {
      sampleCatalog = null;
      $("sample-grid").replaceChildren(node("p", "research-empty", "Catalogue is unavailable right now."));
    });
}

if ($("samples")) {
  $("sample-search").addEventListener("input", renderSamples);
  $("sample-category").addEventListener("change", renderSamples);
  $("sample-platform").addEventListener("change", renderSamples);
  $("sample-severity").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-severity]");
    if (!button) return;
    sampleSeverity = button.dataset.severity;
    for (const other of $("sample-severity").querySelectorAll("button")) other.setAttribute("aria-pressed", String(other === button));
    renderSamples();
  });
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) { observer.disconnect(); loadSamples(); }
    }, { rootMargin: "400px" });
    observer.observe($("samples"));
  } else {
    loadSamples();
  }
}
