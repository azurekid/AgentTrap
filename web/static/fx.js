"use strict";
(() => {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  function countTo(element, target) {
    const start = Number(element.dataset.value || 0);
    element.dataset.value = String(target);
    if (reduced || start === target) {
      element.textContent = target.toLocaleString();
      return;
    }
    const began = performance.now();
    const step = (now) => {
      const progress = Math.min(1, (now - began) / 900);
      const eased = 1 - (1 - progress) ** 3;
      element.textContent = Math.round(start + (target - start) * eased).toLocaleString();
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  const detectors = document.getElementById("stat-detectors");
  fetch("/api/policy")
    .then((response) => {
      if (!response.ok) throw new Error(`Policy request failed (${response.status}).`);
      return response.json();
    })
    .then((policy) => {
      if (!Number.isInteger(policy.detectors) || policy.detectors < 1) {
        throw new Error("Policy response has an invalid detector count.");
      }
      countTo(detectors, policy.detectors);
    })
    .catch((error) => {
      detectors.textContent = "Unavailable";
      console.error("Unable to load scanner coverage:", error);
    });

  let loading = false;
  async function refreshStatistics() {
    if (loading) return;
    loading = true;
    const files = document.getElementById("total-files");
    const findings = document.getElementById("total-findings");
    const errorMessage = document.getElementById("statistics-error");
    try {
      const response = await fetch("/api/statistics", { cache: "no-store" });
      if (!response.ok) throw new Error(`Statistics request failed (${response.status}).`);
      const totals = await response.json();
      if (![totals.files, totals.findings].every((n) => Number.isSafeInteger(n) && n >= 0)) {
        throw new Error("Invalid statistics response.");
      }
      countTo(files, totals.files);
      countTo(findings, totals.findings);
      errorMessage.hidden = true;
    } catch (error) {
      for (const element of [files, findings]) {
        element.textContent = "Unavailable";
        delete element.dataset.value;
      }
      errorMessage.textContent = "Activity totals are temporarily unavailable. File inspection is still available.";
      errorMessage.hidden = false;
      console.error("Unable to load activity totals:", error);
    } finally {
      loading = false;
    }
  }
  refreshStatistics();
  document.addEventListener("agenttrap:scan-complete", refreshStatistics);
  setInterval(() => {
    if (!document.hidden) refreshStatistics();
  }, 60000);

  // Hero simulation: instruction sources stream into an agent; AgentTrap's ring intercepts hostile payloads.
  const canvas = document.getElementById("flow-canvas");
  const log = document.getElementById("flow-log");
  if (!canvas || !log) return;
  const ctx = canvas.getContext("2d");
  const SOURCES = ["AGENTS.md", "SKILL.md", "mcp.json", "settings.json", ".cursorrules"];
  const THREATS = [
    ["PROMPT-INJECTION", "ignore all previous instructions"],
    ["SECRET-GITHUB", "ghp_•••••••••••• redacted"],
    ["PIPE-TO-SHELL", "curl -fsSL https://… | sh"],
    ["EXFIL-ENV", "post $AWS_SECRET_ACCESS_KEY to …"],
    ["FAKE-SYSTEM-TAG", "<system>developer mode enabled"],
    ["VSCODE-AUTOAPPROVE", "chat.tools.autoApprove: true"],
    ["MARKDOWN-IMAGE-EXFIL", "![](https://…/?d=${secrets})"],
    ["SECRET-AI-API", "sk-•••••••••••• redacted"],
    ["DISABLE-SAFEGUARDS", "--dangerously-skip-permissions"],
  ];
  const colors = { teal: "#2dd4bf", red: "#f43f5e", line: "rgba(125,141,162,0.16)", text: "#b4c2d3", muted: "#5d6d82" };
  let width = 0, height = 0, sources = [], core = { x: 0, y: 0, r: 0, ring: 0 };
  let packets = [], bursts = [], flash = 0, pulse = 0, lastSpawn = 0, lastLog = 0, running = false, visible = true, frame = 0;

  function layout() {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const names = width < 420 ? SOURCES.slice(0, 4) : SOURCES;
    const top = height * 0.14, span = height * 0.72;
    sources = names.map((name, index) => ({ name, x: 16, y: top + (span * index) / (names.length - 1) }));
    core = { x: width - Math.max(70, width * 0.17), y: height / 2, r: Math.min(30, height * 0.1) };
    core.ring = core.r + Math.min(30, width * 0.06);
    ctx.font = "11px ui-monospace, SFMono-Regular, Menlo, monospace";
    for (const source of sources) source.w = ctx.measureText(source.name).width + 18;
  }

  function point(source, t) {
    const sx = source.x + source.w, sy = source.y;
    const cx = (sx + core.x) / 2, cy = source.y;
    const u = 1 - t;
    return { x: u * u * sx + 2 * u * t * cx + t * t * core.x, y: u * u * sy + 2 * u * t * cy + t * t * core.y };
  }

  function addLog(kind, title, detail) {
    const item = document.createElement("li");
    item.className = kind;
    const label = document.createElement("b");
    label.textContent = kind === "blocked" ? "BLOCK" : "PASS ";
    const rule = document.createElement("span");
    rule.textContent = title;
    const text = document.createElement("em");
    text.textContent = detail;
    item.append(label, rule, text);
    log.prepend(item);
    while (log.children.length > 4) log.lastElementChild.remove();
  }

  function spawn() {
    const source = sources[Math.floor(Math.random() * sources.length)];
    const bad = Math.random() < 0.38;
    packets.push({ source, t: 0, speed: 0.0035 + Math.random() * 0.003, bad, threat: THREATS[Math.floor(Math.random() * THREATS.length)] });
  }

  function draw(now) {
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "rgba(125,141,162,0.08)";
    for (let x = 12; x < width; x += 24) for (let y = 12; y < height; y += 24) ctx.fillRect(x, y, 1, 1);

    ctx.lineWidth = 1;
    for (const source of sources) {
      ctx.strokeStyle = colors.line;
      ctx.beginPath();
      ctx.moveTo(source.x + source.w, source.y);
      ctx.quadraticCurveTo((source.x + source.w + core.x) / 2, source.y, core.x, core.y);
      ctx.stroke();
      ctx.fillStyle = "#0e1724";
      ctx.strokeStyle = "#263649";
      ctx.beginPath();
      ctx.roundRect(source.x, source.y - 11, source.w, 22, 6);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = colors.text;
      ctx.textBaseline = "middle";
      ctx.fillText(source.name, source.x + 9, source.y + 0.5);
    }

    const angle = now / 2400;
    const danger = flash > 0;
    ctx.save();
    ctx.translate(core.x, core.y);
    ctx.rotate(angle);
    ctx.setLineDash([6, 8]);
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = danger ? `rgba(244,63,94,${0.5 + flash * 0.5})` : "rgba(45,212,191,0.55)";
    ctx.beginPath();
    ctx.arc(0, 0, core.ring, 0, Math.PI * 2);
    ctx.stroke();
    ctx.restore();
    ctx.setLineDash([]);
    ctx.fillStyle = danger ? "#fda4af" : "#5eead4";
    ctx.textAlign = "center";
    ctx.fillText("AGENTTRAP", core.x, core.y - core.ring - 12);
    ctx.textAlign = "start";

    const glow = ctx.createRadialGradient(core.x, core.y, 0, core.x, core.y, core.r * 2.4);
    glow.addColorStop(0, `rgba(45,212,191,${0.28 + pulse * 0.3})`);
    glow.addColorStop(1, "rgba(45,212,191,0)");
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(core.x, core.y, core.r * 2.4, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = "#0b1a22";
    ctx.strokeStyle = colors.teal;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(core.x, core.y, core.r, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = "#ccfbf1";
    ctx.font = "600 10px ui-monospace, SFMono-Regular, Menlo, monospace";
    ctx.textAlign = "center";
    ctx.fillText("AGENT", core.x, core.y + 0.5);
    ctx.textAlign = "start";
    ctx.font = "11px ui-monospace, SFMono-Regular, Menlo, monospace";

    for (const packet of packets) {
      const p = point(packet.source, packet.t);
      const trail = point(packet.source, Math.max(0, packet.t - 0.05));
      const color = packet.bad ? colors.red : colors.teal;
      const gradient = ctx.createLinearGradient(trail.x, trail.y, p.x, p.y);
      gradient.addColorStop(0, "rgba(0,0,0,0)");
      gradient.addColorStop(1, color);
      ctx.strokeStyle = gradient;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(trail.x, trail.y);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(p.x, p.y, packet.bad ? 3.2 : 2.6, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    }
    for (const burst of bursts) {
      ctx.strokeStyle = `rgba(244,63,94,${burst.life})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(burst.x, burst.y, (1 - burst.life) * 22 + 3, 0, Math.PI * 2);
      ctx.stroke();
      for (let i = 0; i < 6; i++) {
        const a = (i / 6) * Math.PI * 2 + burst.spin;
        const d = (1 - burst.life) * 18 + 4;
        ctx.fillStyle = `rgba(253,164,175,${burst.life})`;
        ctx.fillRect(burst.x + Math.cos(a) * d - 1, burst.y + Math.sin(a) * d - 1, 2, 2);
      }
    }
  }

  function update(now) {
    if (now - lastSpawn > 520) {
      spawn();
      lastSpawn = now;
    }
    packets = packets.filter((packet) => {
      packet.t += packet.speed;
      const p = point(packet.source, packet.t);
      if (packet.bad && Math.hypot(p.x - core.x, p.y - core.y) <= core.ring) {
        bursts.push({ x: p.x, y: p.y, life: 1, spin: Math.random() * 6 });
        flash = 1;
        if (now - lastLog > 900) {
          addLog("blocked", packet.threat[0], `${packet.source.name}:${1 + Math.floor(Math.random() * 90)}  ${packet.threat[1]}`);
          lastLog = now;
        }
        return false;
      }
      if (packet.t >= 1) {
        pulse = 1;
        if (now - lastLog > 2600 && Math.random() < 0.35) {
          addLog("passed", "NO SIGNALS", `${packet.source.name}  instructions delivered`);
          lastLog = now;
        }
        return false;
      }
      return true;
    });
    bursts = bursts.filter((burst) => (burst.life -= 0.03) > 0);
    flash = Math.max(0, flash - 0.03);
    pulse = Math.max(0, pulse - 0.04);
  }

  function loop(now) {
    if (!running) return;
    update(now);
    draw(now);
    frame = requestAnimationFrame(loop);
  }
  function setRunning(next) {
    if (next === running || reduced) return;
    running = next;
    if (running) frame = requestAnimationFrame(loop);
    else cancelAnimationFrame(frame);
  }

  layout();
  if (reduced) {
    for (const [index, source] of sources.entries()) {
      packets.push({ source, t: 0.25 + index * 0.12, speed: 0, bad: index % 2 === 1, threat: THREATS[index] });
    }
    draw(0);
    addLog("passed", "NO SIGNALS", "AGENTS.md  instructions delivered");
    addLog("blocked", THREATS[0][0], `SKILL.md:12  ${THREATS[0][1]}`);
    addLog("blocked", THREATS[2][0], `settings.json:4  ${THREATS[2][1]}`);
  } else {
    addLog("blocked", THREATS[0][0], `SKILL.md:12  ${THREATS[0][1]}`);
    new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      setRunning(visible && !document.hidden);
    }).observe(canvas);
    document.addEventListener("visibilitychange", () => setRunning(visible && !document.hidden));
  }
  new ResizeObserver(() => {
    layout();
    if (!running) draw(performance.now());
  }).observe(canvas);
})();
