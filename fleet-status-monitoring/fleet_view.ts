import { type FleetState, State } from "./fleet_contract.ts";
import { ViewOptions } from "./view_options.ts";
import { fleetControls } from "./fleet_controls.ts";
const esc = (x: unknown) =>
  String(x ?? "Unknown").replace(
    /[&<>"']/g,
    (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]!),
  );
const healthLabel = (s: string) => ({
  healthy: "Healthy",
  attention: "Needs attention",
  unknown: "Unknown",
  stale: "Stale",
  unreachable: "Unreachable",
  "access-required": "Needs access",
  unsupported: "Not configured",
}[s] ?? s);
const gib = (n: number | null) =>
  n === null ? "Unknown" : (n / 1024 ** 3).toFixed(1) + " GiB";
const pct = (a: number | null, t: number | null) =>
  a === null || t === null || t <= 0
    ? "Unknown"
    : (a / t * 100).toFixed(0) + "%";
const duration = (n: number | null) =>
  n === null
    ? "Unknown"
    : n >= 86400
    ? (n / 86400).toFixed(1) + " days"
    : n >= 3600
    ? (n / 3600).toFixed(1) + " hours"
    : Math.floor(n / 60) + " min";
/** Render validated fleet state with same-origin configurable navigation. */
export function renderFleet(input: FleetState, options: unknown = {}): string {
  const state = State.parse(input);
  const view = ViewOptions.parse(options);
  const settings = JSON.stringify({ refreshPath: view.reportPath + "/refresh" })
    .replace(/</g, "\\u003c");
  const rows = state.systems.map((r) => {
    const s = r.sample;
    return `<article class="system" data-group="${
      esc(r.group)
    }" data-health="${r.health}" data-name="${
      esc(r.label.toLowerCase())
    }" data-observed="${esc(s?.observedAt ?? "")}"><header><h2>${
      esc(r.label)
    }</h2><span class="badge ${r.health}">${
      healthLabel(r.health)
    }</span></header><p class="os">${
      s
        ? esc(
          s.osName + " " + (s.osVersion ?? "Unknown version") + " · " +
            s.architecture,
        )
        : "No current system observation"
    }</p><dl><dt>CPU</dt><dd>${
      s
        ? esc(s.logicalCores) + " logical cores · " +
          esc(s.load1?.toFixed(2) ?? "Unknown") + " load (1 min)"
        : "Unknown"
    }</dd><dt>Memory headroom</dt><dd>${
      s
        ? gib(s.memoryAvailableBytes) + " / " + gib(s.memoryTotalBytes) + " (" +
          pct(s.memoryAvailableBytes, s.memoryTotalBytes) + ")"
        : "Unknown"
    }</dd><dt>Startup data free</dt><dd>${
      s
        ? gib(s.diskAvailableBytes) + " / " + gib(s.diskTotalBytes) + " (" +
          pct(s.diskAvailableBytes, s.diskTotalBytes) + ")"
        : "Unknown"
    }</dd><dt>Uptime</dt><dd>${
      duration(s?.uptimeSeconds ?? null)
    }</dd><dt>Last observed</dt><dd><time>${
      esc(s?.observedAt ?? "Not observed")
    }</time></dd></dl><p class="issues">${
      esc(r.issues.join(" · ") || "Within the configured thresholds")
    }</p><details><summary>Evidence and measurement notes</summary><p>Scan ${
      esc(r.cycleId)
    } · transport version ${
      esc(
        r.sourceVersion ??
          (r.collector === "local" ? "Local server observation" : "None"),
      )
    } · workflow ${
      esc(r.sourceWorkflowRunId ?? state.workflowRunId ?? "Unavailable")
    }</p><p>Memory: ${
      esc(s?.memoryAvailableKind ?? "Unavailable")
    }. Disk: startup data filesystem only; APFS shared capacity is not summed. Load is a queue measure, not CPU utilization.</p><p>Kernel ${
      esc(s?.kernel ?? "Unknown")
    } · ${esc(r.kind)} · ${esc(r.note)}</p></details></article>`;
  }).join("");
  const json = JSON.stringify(state).replace(/</g, "\\u003c");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fleet Status Monitoring</title><style>
 :root{color-scheme:dark;
font-family:system-ui,sans-serif;
background:#101820;
color:#e9f2f0}
*{box-sizing:border-box}
body{max-width:1100px;
margin:auto;
padding:24px}
a{color:#9ee6bd}
h1{font-size:clamp(1.8rem,5vw,2.8rem);
margin:12px 0}
h2{font-size:1.3rem;
margin:0}
p{line-height:1.5;
color:#b8cbc8}
nav{display:flex;
gap:20px;
flex-wrap:wrap}
.stats{display:grid;
grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
gap:12px;
margin:24px 0}
.stat,.system{background:#192831;
border:1px solid #345051;
border-radius:14px;
padding:20px}
.stat strong{display:block;
font-size:2rem;
color:#b2efcb}
.controls{display:flex;
flex-wrap:wrap;
align-items:end;
gap:12px;
margin-bottom:20px}
label{display:grid;
gap:6px;
font-size:.9rem}
input,select,button{font:inherit;
color:inherit;
background:#20363c;
border:1px solid #527176;
border-radius:8px;
padding:10px;
min-height:44px}
input{max-width:220px}
button{cursor:pointer}
button.primary{background:#b2efcb;
color:#12251e;
font-weight:700}
button:disabled{opacity:.6;
cursor:wait}
.grid{display:grid;
grid-template-columns:repeat(auto-fit,minmax(min(100%,310px),1fr));
gap:16px}
article header{display:flex;
align-items:center;
justify-content:space-between;
gap:12px}
.badge{border-radius:20px;
padding:5px 10px;
background:#354951;
font-size:.85rem}
.healthy{background:#214c3b;
color:#bcf5d0}
.attention{background:#664f25;
color:#ffe0a0}
.unreachable,.unknown,.stale,.access-required{background:#5d3733;
color:#ffd0c4}
dl{display:grid;
grid-template-columns:1fr;
gap:4px}
dt{font-size:.83rem;
color:#91a9a6;
margin-top:10px}
dd{margin:0}
time{font-size:.85rem;
overflow-wrap:anywhere}
details{font-size:.85rem;
overflow-wrap:anywhere}
summary{cursor:pointer;
padding:8px 0}
.issues{min-height:1.5em;
font-size:.9rem}
[hidden]{display:none!important}
.foot{margin-top:28px;
font-size:.85rem}
#action-status{min-height:1.6em}
footer{border-top:1px solid #345051;
margin-top:24px;
padding-top:16px}

 </style></head><body><nav>${
    view.dashboardPath
      ? `<a href="${esc(view.dashboardPath)}">Open Swamp dashboard</a>`
      : ""
  }${
    view.questPath ? `<a href="${esc(view.questPath)}">Quest report</a>` : ""
  }</nav><p>Swamp · Fleet health</p><h1>Fleet Status Monitoring</h1><p>Small, read-only checks for the systems you care about. Missing data stays visible.</p>
 <div class="stats"><div class="stat"><strong>${state.totals.configured}</strong>Systems configured</div><div class="stat"><strong id="scanned">${state.totals.scanned}</strong>Systems checked</div><div class="stat"><strong id="healthy">${state.totals.healthy}</strong>Healthy</div><div class="stat"><strong id="attention">${state.totals.attention}</strong>Need attention</div><div class="stat"><strong id="gaps">${state.totals.gaps}</strong>Coverage gaps</div></div>
 <div class="controls"><label>Find system<input id="query" type="search" placeholder="System name"></label><label>Group<select id="group"><option value="all">All groups</option>${
    [...new Set(state.systems.map((r) => r.group))].map((g) =>
      `<option>${esc(g)}</option>`
    ).join("")
  }</select></label><label>Status<select id="status"><option value="all">All statuses</option>${
    [
      "healthy",
      "attention",
      "unknown",
      "stale",
      "unreachable",
      "access-required",
      "unsupported",
    ]
      .map((x) => `<option value="${x}">${healthLabel(x)}</option>`).join("")
  }</select></label><button id="filter">Apply filters</button><button class="primary" id="refresh">Refresh live status</button></div><p id="action-status" role="status" aria-live="polite">Snapshot ${
    esc(state.generatedAt)
  } · stale after ${
    state.policy.maxAgeSeconds / 60
  } minutes</p><p id="visible-count"></p><div class="grid">${rows}</div><p id="empty" hidden>No systems match these filters.</p>
 <footer><details open><summary>What these checks mean</summary><p>Attention thresholds: memory headroom below ${state.policy.minMemoryPercent}%; startup-data free space below ${state.policy.minDiskPercent}% or ${
    gib(state.policy.minDiskBytes)
  }; one-minute load above ${state.policy.maxLoadPerCore} per logical core. These are configured operating signals, not a diagnosis or security assessment.</p><p>OS versions observed: ${
    esc(
      state.operatingSystems.map((o) =>
        o.family + " " + o.version + " (" + o.count + ")"
      ).join(", ") || "None yet",
    )
  }. Unknown values are never displayed as zero.</p>${
    state.exclusions.map((x) => `<p>${esc(x)}</p>`).join("")
  }<p>Every refresh runs only the named fleet workflow on Swamp Server. Changing filters does not run checks. No automatic repairs.</p></details><details><summary>State report</summary><pre id="state-report" style="white-space:pre-wrap"></pre></details></footer>
 <script id="fleet-state" type="application/json">${json}</script><script id="fleet-view-settings" type="application/json">${settings}</script><script>${fleetControls} </script></body></html>`;
}
