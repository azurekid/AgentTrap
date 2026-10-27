"use strict";
const $ = (id) => document.getElementById(id);
function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

let data = null;
const CATEGORIES = { cve: "advisory", poc: "PoC" };
// Group raw types such as "blog/CVE-2025-53773" or "paper (USENIX Sec 2025)" into one filter category.
function category(type) {
  const base = type.split(/[\/( ]/)[0].toLowerCase();
  return CATEGORIES[base] || base;
}
let activeType = "all";

function matches(source, query) {
  if (activeType !== "all" && category(source.type) !== activeType) return false;
  if (!query) return true;
  return [source.title, source.author, source.date, source.type, source.note, ...source.urls].join(" ").toLowerCase().includes(query);
}

function render() {
  const query = $("research-search").value.trim().toLowerCase();
  const root = $("sources");
  root.replaceChildren();
  let shown = 0;
  for (const section of data.sections) {
    const visible = section.sources.filter((source) => matches(source, query));
    if (!visible.length) continue;
    shown += visible.length;
    const heading = node("h2", "", section.heading);
    heading.append(node("span", "", `${visible.length} source${visible.length === 1 ? "" : "s"}`));
    const grid = node("div", "source-grid");
    for (const source of visible) {
      const card = node("article", "source");
      card.id = `source-${source.id}`;
      const number = node("a", "source-num", source.id);
      number.href = `#source-${source.id}`;
      number.setAttribute("aria-label", `Source ${source.id}`);
      const meta = node("p", "source-meta", [source.author, source.date].filter(Boolean).join(" · "));
      if (source.type) meta.append(node("span", "source-type", source.type));
      card.append(number, node("h3", "", source.title), meta);
      if (source.urls.length) {
        const links = node("ul", "source-links");
        for (const url of source.urls) {
          const item = node("li");
          const link = node("a", "", url.replace(/^https?:\/\//, ""));
          link.href = url;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          item.append(link);
          links.append(item);
        }
        card.append(links);
      }
      if (source.note) card.append(node("p", "source-note", source.note));
      grid.append(card);
    }
    root.append(heading, grid);
  }
  if (!shown) root.append(node("p", "research-empty", "No sources match this filter."));
  const total = data.sections.reduce((sum, section) => sum + section.sources.length, 0);
  $("research-count").textContent = shown === total ? `${total} sources` : `${shown} of ${total}`;
}

function renderTypes() {
  const types = [...new Set(data.sections.flatMap((section) => section.sources.map((source) => category(source.type))).filter(Boolean))].sort((a, b) => a.localeCompare(b, "en", { sensitivity: "base" }));
  for (const type of ["all", ...types]) {
    const button = node("button", "", type === "all" ? "All" : type);
    button.type = "button";
    button.setAttribute("aria-pressed", String(type === activeType));
    button.addEventListener("click", () => {
      activeType = type;
      for (const other of $("research-types").children) other.setAttribute("aria-pressed", String(other === button));
      render();
    });
    $("research-types").append(button);
  }
}

function focusHash() {
  for (const card of document.querySelectorAll(".source.targeted")) card.classList.remove("targeted");
  const match = /^#source-(\d+)$/.exec(location.hash);
  const target = match && $(`source-${match[1]}`);
  if (!target) return;
  target.classList.add("targeted");
  target.scrollIntoView({ block: "center" });
}

async function load() {
  try {
    const response = await fetch("/api/sources", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(String(response.status));
    data = await response.json();
  } catch {
    $("research-intro").textContent = "Research sources could not be loaded. Please try again later.";
    return;
  }
  $("research-title").textContent = data.title || "Research sources";
  $("research-intro").textContent = data.intro;
  renderTypes();
  render();
  $("research-search").addEventListener("input", render);
  focusHash();
  window.addEventListener("hashchange", focusHash);
}

load();
