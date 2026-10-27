"use strict";
const $ = (id) => document.getElementById(id);
let mode = "upload";
let selected = [];
let report = null;
let busy = false;
let discover = false;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
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
  $("error").hidden = true;
}
$("upload-tab").addEventListener("click", () => changeMode("upload"));
for (const link of document.querySelectorAll("[data-mode]")) {
  link.addEventListener("click", () => changeMode(link.dataset.mode === "repo" ? "repo" : "upload"));
}
$("repo-tab").addEventListener("click", () => changeMode("repo"));
document.querySelector(".tabs").addEventListener("keydown", (event) => {
  if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    event.preventDefault();
    changeMode(mode === "upload" ? "repo" : "upload");
    $(mode === "upload" ? "upload-tab" : "repo-tab").focus();
  }
});

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
      || /\/\.(cursor|cline|clinerules)\/(?:rules\/)?[^/]+$/.test(file.webkitRelativePath));
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
$("files").addEventListener("change", (event) => setFiles(event.target.files));
$("folder").addEventListener("change", (event) => setFiles(event.target.files, true));
for (const name of ["dragover", "dragleave", "drop"]) {
  $("dropzone").addEventListener(name, (event) => {
    event.preventDefault();
    $("dropzone").classList.toggle("drag-over", name === "dragover");
    if (name === "drop") setFiles(event.dataTransfer.files);
  });
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
    label.append(svg("tspan", { x, dy: 15, class: "axis-count" }, tactic.findings ? `${tactic.findings} finding${tactic.findings === 1 ? "" : "s"}` : "—"));
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
      guidance.append(node("b", "", "AgentTrap guidance: "), tech.guidance);
      block.append(guidance);
    }
    card.append(block);
    $("atlas-techniques").append(card);
  }
}

function renderResults() {
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
      ? "No supported agent files found — this is not a clean bill of health."
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
  if (!report.skipped.length && report.archive.status !== "stored" && report.archive.status !== "failed") {
    $("report-notes").append(node("p", "", "All discovered files were inspected."));
  }
  if (report.archive.status === "stored") {
    $("report-notes").append(node("p", "warning", `${report.archive.files} high-risk file(s) retained in the private investigation archive for 30 days.`));
  } else if (report.archive.status === "failed") {
    $("report-notes").append(node("p", "warning", report.archive.message));
  }
  for (const path of report.skipped) $("report-notes").append(node("p", "warning", `Not inspected: ${path}`));
  if (report.statistics?.status === "failed") {
    $("report-notes").append(node("p", "warning", report.statistics.message));
  }
  $("disclaimer").textContent = report.disclaimer;
  $("finding-count").textContent = `${summary.findings} signals across ${summary.files} files`;
  $("severity").value = "ALL";
  renderAtlas(report.atlas);
  renderFindings();
  $("results").hidden = false;
  $("results").scrollIntoView({
    behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth",
    block: "start",
  });
}
function renderFindings() {
  $("findings").replaceChildren();
  const filter = $("severity").value;
  let visible = 0;
  for (const file of report.files) {
    const findings = file.findings.filter((finding) => filter === "ALL" || finding.severity === filter);
    if (!findings.length && filter !== "ALL") continue;
    visible++;
    const details = node("details", "file-result");
    details.open = findings.length > 0;
    const summary = node("summary", "", file.path);
    summary.append(node("span", "", `${findings.length} finding(s)${file.findings.length === 0 ? " · No signals detected" : ""}`));
    details.append(summary);
    if (!findings.length) details.append(node("div", "empty-state", "No security signals detected by the current rules. Manual review is still recommended."));
    for (const finding of findings) {
      const article = node("article", `finding sev-${finding.severity.toLowerCase()}`);
      const heading = node("div", "finding-heading");
      heading.append(node("span", `badge ${finding.severity.toLowerCase()}`, finding.severity),
        node("strong", "", finding.rule), node("span", "line-number", `LINE ${finding.line}`));
      article.append(heading, node("p", "", finding.message), node("pre", "", finding.snippet));
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
      if (finding.ref) {
        const refs = node("p", "refs", "Research: ");
        for (const id of finding.ref.split(",").map((value) => value.trim()).filter((value) => /^\d+$/.test(value))) {
          const link = node("a", "", `#${id}`);
          link.href = `/sources#source-${id}`;
          link.target = "_blank";
          link.rel = "noopener";
          refs.append(link, " ");
        }
        article.append(refs);
      }
      details.append(article);
    }
    $("findings").append(details);
  }
  if (!visible) $("findings").append(node("div", "empty-state", "No files match this severity filter."));
}
$("severity").addEventListener("change", renderFindings);
$("download").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = node("a");
  link.href = url;
  link.download = `agenttrap-${report.id}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  $("error").hidden = true;
  $("results").hidden = true;
  let body;
  const headers = {};
  const workflows = mode === "repo" && $("workflows").checked;
  if (mode === "upload") {
    if (!selected.length) return showError("Select at least one file to inspect.");
    if (selected.length > 100 || selected.some((file) => file.size > 256 * 1024)
      || selected.reduce((total, file) => total + file.size, 0) > 2 * 1024 * 1024) {
      return showError("Select up to 100 files, at most 256 KiB each and 2 MiB combined.");
    }
    body = new FormData();
    body.append("include_workflows", String(workflows));
    body.append("discover", String(discover));
    for (const file of selected) body.append("files", file, file.webkitRelativePath || file.name);
  } else {
    const url = $("repository").value.trim();
    if (!url) return showError("Enter a public GitHub repository URL.");
    body = JSON.stringify({ url, include_workflows: workflows });
    headers["Content-Type"] = "application/json";
  }
  busy = true;
  setScanning(true);
  $("scan-button").disabled = true;
  $("scan-button").textContent = "Inspecting…";
  $("progress").hidden = false;
  for (const id of ["files", "folder", "repository", "workflows"]) $(id).disabled = true;
  renderFiles();
  try {
    const response = await fetch(`/api/scan/${mode === "upload" ? "files" : "repository"}`, { method: "POST", body, headers, signal: AbortSignal.timeout(90000) });
    if (!response.headers.get("content-type")?.includes("application/json")) throw new Error("The scan service returned an unexpected response. Try again later.");
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The request was rejected. Check your selected files.");
    report = data;
    renderResults();
    document.dispatchEvent(new Event("agenttrap:scan-complete"));
  } catch (error) {
    showError(error.name === "TimeoutError" ? "The request timed out. No complete result is available." : error.message || "Unable to reach the scanner.");
  } finally {
    busy = false;
    setScanning(false);
    $("scan-button").disabled = false;
    $("scan-button").replaceChildren(document.createTextNode("Run inspection "), node("span", "", "→"));
    $("progress").hidden = true;
    for (const id of ["files", "folder", "repository", "workflows"]) $(id).disabled = false;
    $("repository").disabled = mode !== "repo";
    renderFiles();
  }
});
