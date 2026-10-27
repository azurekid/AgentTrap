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
      guidance.append(node("b", "", "SkillVenom guidance: "), tech.guidance);
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
  } else if (report.archive.status === "opted_out") {
    $("report-notes").append(node("p", "meta", "Investigation retention opted out: no files were retained."));
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
}
function renderFindings() {
  $("findings").replaceChildren();
  const filter = $("severity").value;
  let visible = 0;
  const clean = report.files.filter((file) => !file.findings.length).length;
  for (const file of report.files) {
    const findings = file.findings.filter((finding) => filter === "ALL" || finding.severity === filter);
    if (!findings.length) continue;
    visible++;
    const details = node("details", "file-result");
    details.open = true;
    const summary = node("summary", "", file.path);
    summary.append(node("span", "", `${findings.length} finding(s)`));
    details.append(summary);
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
      : "No files match this severity filter.";
    $("findings").append(node("div", "empty-state", message));
  }
  if (clean) $("findings").append(node("p", "clean-note", `${clean} scanned ${clean === 1 ? "file" : "files"} with no findings ${clean === 1 ? "is" : "are"} not listed.`));
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
    label.append(box, node("span", `badge ${f.severity.toLowerCase()}`, f.severity), node("code", "", f.rule), node("span", "meta", `${f.path}:${f.line}`));
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

  fetch("/api/sources", { headers: { Accept: "application/json" } })
    .then((response) => (response.ok ? response.json() : null))
    .then((data) => {
      if (!data) return;
      sourceIndex = new Map(data.sections.flatMap((section) => section.sources.map((source) => [source.id, source])));
      if (report) renderFindings();
    })
    .catch(() => {});
  $("download").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = node("a");
    link.href = url;
    link.download = `skillvenom-${report.id}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  let stored = null;
  try { stored = JSON.parse(sessionStorage.getItem(REPORT_KEY)); } catch { /* ignore */ }
  if (stored?.files && stored?.atlas) {
    report = stored;
    renderResults();
  } else {
    $("results").hidden = true;
    $("no-report").hidden = false;
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
    const consent = $("archive-consent").checked;
    if (mode === "upload") {
      if (!selected.length) return showError("Select at least one file to inspect.");
      if (selected.length > 100 || selected.some((file) => file.size > 256 * 1024)
        || selected.reduce((total, file) => total + file.size, 0) > 2 * 1024 * 1024) {
        return showError("Select up to 100 files, at most 256 KiB each and 2 MiB combined.");
      }
      body = new FormData();
      body.append("include_workflows", String(workflows));
      body.append("discover", String(discover));
      body.append("archive_consent", String(consent));
      for (const file of selected) body.append("files", file, file.webkitRelativePath || file.name);
    } else {
      const url = $("repository").value.trim();
      if (!url) return showError("Enter a repository URL.");
      const token = $("private-repo").checked ? $("repo-token").value.trim() : "";
      body = JSON.stringify({ url, include_workflows: workflows, archive_consent: consent, ...(token && { token }) });
      headers["Content-Type"] = "application/json";
    }
    busy = true;
    setScanning(true);
    $("scan-button").disabled = true;
    $("scan-button").textContent = "Inspecting…";
    $("progress").hidden = false;
    for (const id of ["files", "folder", "repository", "private-repo", "repo-token", "workflows", "archive-consent"]) $(id).disabled = true;
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
      for (const id of ["files", "folder", "repository", "private-repo", "repo-token", "workflows", "archive-consent"]) $(id).disabled = false;
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
