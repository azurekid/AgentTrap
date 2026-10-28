"use strict";
const AgentLensRadar = (() => {
  const SHORT = { "command-and-control": ["Command &", "Control"], "credential-access": ["Credential", "Access"], "defense-evasion": ["Defense", "Evasion"], "initial-access": ["Initial", "Access"] };
  function svg(tag, attrs = {}, text) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, String(value));
    if (text !== undefined) element.textContent = text;
    return element;
  }
  function draw(radar, tactics) {
    radar.setAttribute("viewBox", "-45 0 560 420");
    radar.replaceChildren(svg("title", {}, "Finding occurrences per MITRE ATLAS tactic"));
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
    // Square-root scaling keeps small counts visible beside a dominant tactic.
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
  return { draw };
})();
