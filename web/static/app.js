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
$("repo-tab").addEventListener("click", () => changeMode("repo"));
document.querySelector(".tabs").addEventListener("keydown", (event) => {
  if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    event.preventDefault();
    changeMode(mode === "upload" ? "repo" : "upload");
    $(mode === "upload" ? "upload-tab" : "repo-tab").focus();
  }
});

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

function renderResults() {
  const summary = report.summary;
  const incomplete = report.status === "partial" || report.status === "no_targets";
  $("verdict").className = "verdict" + (summary.severities.CRITICAL || summary.severities.HIGH || incomplete ? " risky" : "");
  $("verdict").textContent = report.status === "no_targets"
    ? "NO TARGET FILES — No supported agent files were found. This is not a clean bill of health."
    : `${report.status === "partial" ? "PARTIAL SCAN · " : ""}${summary.verdict} · ${summary.findings} finding${summary.findings === 1 ? "" : "s"}`;
  $("metrics").replaceChildren();
  for (const [label, value, severity] of [
    ["FILES SCANNED", summary.files, ""], ["CRITICAL", summary.severities.CRITICAL, "critical"],
    ["HIGH", summary.severities.HIGH, "high"], ["MEDIUM", summary.severities.MEDIUM, "medium"],
    ["LOW", summary.severities.LOW, "low"],
  ]) {
    const card = node("div", "metric");
    card.append(node("strong", severity, String(value)), node("span", "", label));
    $("metrics").append(card);
  }
  $("report-notes").replaceChildren(node("p", "", `${report.source} · ${new Date(report.created_at).toLocaleString()}`));
  if (report.commit) $("report-notes").append(node("p", "", `Inspected commit: ${report.commit}`));
  if (report.archive.status === "stored") {
    $("report-notes").append(node("p", "warning", `${report.archive.files} high-risk file(s) retained in the private investigation archive for 30 days.`));
  } else if (report.archive.status === "failed") {
    $("report-notes").append(node("p", "warning", report.archive.message));
  }
  for (const path of report.skipped) $("report-notes").append(node("p", "warning", `Not inspected: ${path}`));
  $("disclaimer").textContent = report.disclaimer;
  $("finding-count").textContent = `${summary.findings} signals across ${summary.files} files`;
  $("severity").value = "ALL";
  renderFindings();
  $("results").hidden = false;
  $("results").scrollIntoView({ behavior: "smooth", block: "start" });
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
      const article = node("article", "finding");
      const heading = node("div", "finding-heading");
      heading.append(node("span", `badge ${finding.severity.toLowerCase()}`, finding.severity),
        node("strong", "", finding.rule), node("span", "line-number", `LINE ${finding.line}`));
      article.append(heading, node("p", "", finding.message), node("pre", "", finding.snippet));
      if (finding.rule.startsWith("SECRET-")) {
        article.append(node("p", "", "If real: revoke and rotate this credential, remove it from instructions and history, and review access logs. Detection does not verify whether a credential is active."));
      }
      if (finding.ref) {
        const source = node("a", "", `Research references: ${finding.ref}`);
        source.href = "/sources";
        source.target = "_blank";
        source.rel = "noopener";
        article.append(source);
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
  const workflows = $("workflows").checked;
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
  } catch (error) {
    showError(error.name === "TimeoutError" ? "The request timed out. No complete result is available." : error.message || "Unable to reach the scanner.");
  } finally {
    busy = false;
    $("scan-button").disabled = false;
    $("scan-button").replaceChildren(document.createTextNode("Run security scan "), node("span", "", "→"));
    $("progress").hidden = true;
    for (const id of ["files", "folder", "repository", "workflows"]) $(id).disabled = false;
    $("repository").disabled = mode !== "repo";
    renderFiles();
  }
});
