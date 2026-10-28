"use strict";
const AgentLensChecks = (() => {
  const labels = {
    performed: "Checks performed", incomplete: "Partially checked", blocked: "Verification blocked",
    not_applicable: "Not applicable", not_supported: "Outside inspection scope", not_recorded: "Not recorded",
  };
  function render(container, checks, files = [], artifacts = []) {
    container.replaceChildren();
    const signatures = [...files.filter((file) => file.signature).map((file) => file.signature),
      ...artifacts.filter((artifact) => artifact.signature).map((artifact) => artifact.signature)];
    const normalized = checks.map((check) => {
      if (check.status) return check;
      let status = check.performed ? "performed" : "not_recorded";
      let detail = check.performed ? "" : "This older report did not record an outcome for this check. Rescan to refresh coverage.";
      if (["execution", "reputation", "dependencies"].includes(check.id)) {
        status = "not_supported";
        detail = "This inspection does not perform this check.";
      } else if (["publisher", "signatures"].includes(check.id) && signatures.length) {
        const present = signatures.filter((signature) => signature.status !== "unsigned");
        const performed = present.filter((signature) => signature.performed).length;
        status = !present.length ? "not_applicable" : performed === present.length
          ? present.some((signature) => signature.status === "not_verifiable") ? "incomplete" : "performed"
          : performed ? "incomplete" : "blocked";
        detail = present.length ? [...new Set(present.map((signature) => signature.message))].join(" ")
          : "No skill.oms.sig bundle was submitted.";
      } else if (check.id === "mcp" && files.length) {
        const mcp = files.filter((file) => ["complete", "incomplete"].includes(file.mcp?.status));
        status = mcp.some((file) => file.mcp.status === "incomplete") ? "incomplete" : mcp.length ? "performed" : "not_applicable";
        detail = mcp.length ? "Saved MCP tool definitions inspected." : "No saved MCP tool definitions detected.";
      }
      return { ...check, status, detail };
    });
    for (const [status, title] of Object.entries(labels)) {
      const entries = normalized.filter((check) => check.status === status);
      if (!entries.length) continue;
      const group = document.createElement("div");
      group.className = "coverage-check-group";
      const heading = document.createElement("h3");
      heading.textContent = title;
      const list = document.createElement("ul");
      list.className = "coverage-check-list";
      for (const check of entries) {
        const item = document.createElement("li");
        item.className = status === "performed" ? "check-performed" : "check-not-performed";
        item.textContent = check.name;
        if (check.detail) {
          const reason = document.createElement("p");
          reason.className = "meta";
          reason.textContent = check.detail;
          item.append(reason);
        }
        list.append(item);
      }
      group.append(heading, list);
      container.append(group);
    }
  }
  return { render };
})();
