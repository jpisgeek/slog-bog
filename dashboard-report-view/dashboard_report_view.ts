/** Credential-free interactive HTML reports and an embeddable host handler. */
import { z } from "npm:zod@4";

/** A row's explicit observation state; unavailable values remain null. */
export const RowSchema = z.strictObject({
  label: z.string().min(1).max(200),
  value: z.union([z.string().max(2000), z.number().finite(), z.null()]),
  state: z.enum(["healthy", "attention", "unknown", "stale"]),
  evidence: z.string().max(500).optional(),
});
/** Portable data contract; contains no credentials, URLs, or executable HTML. */
export const SnapshotSchema = z.strictObject({
  schemaVersion: z.literal(1),
  title: z.string().min(1).max(200),
  observedAt: z.iso.datetime(),
  sections: z.array(z.strictObject({
    title: z.string().min(1).max(200),
    rows: z.array(RowSchema).max(200),
  })).max(20),
});
/** Validated report state shared by the renderer and host. */
export type Snapshot = z.infer<typeof SnapshotSchema>;
const ArgumentsSchema = z.object({ snapshot: SnapshotSchema });
const escape = (value: unknown): string =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );

/** Render one validated snapshot; all data is escaped before reaching markup. */
export function renderReport(input: unknown): string {
  const snapshot = SnapshotSchema.parse(input);
  const sections = snapshot.sections.map((section) =>
    `<section><h2>${
      escape(section.title)
    }</h2><table><thead><tr><th>Item</th><th>Value</th><th>State</th><th>Evidence</th></tr></thead><tbody>${
      section.rows.map((row) =>
        `<tr data-state="${row.state}"><th scope="row">${
          escape(row.label)
        }</th><td>${
          row.value === null ? "Unavailable" : escape(row.value)
        }</td><td>${row.state}</td><td>${escape(row.evidence ?? "")}</td></tr>`
      ).join("")
    }</tbody></table></section>`
  ).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${
    escape(snapshot.title)
  }</title><style>
:root{color-scheme:dark;font:16px system-ui;background:#101c1a;color:#e4f0eb}
body{max-width:75rem;margin:auto;padding:1.3rem}
h1{font-size:clamp(1.8rem,5vw,3rem)}
section{margin:1.5rem 0;padding:1rem;background:#1b2c27;border-radius:.7rem;overflow:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.7rem;border-bottom:1px solid #496056}
button,input,select{font:inherit;padding:.65rem;border-radius:.4rem;margin:.3rem}label{display:inline-block}tr[data-state=attention]{color:#ffd79c}tr[data-state=stale],tr[data-state=unknown]{color:#ccd0cd}[hidden]{display:none}#feedback{min-height:1.5em}
</style></head>
<body><h1>${
    escape(snapshot.title)
  }</h1><p>Snapshot observed <time datetime="${snapshot.observedAt}">${snapshot.observedAt}</time>. Refresh runs the configured Swamp workflow; filters only change this view.</p>
<label>Filter items <input id="search" type="search"></label>
<label>State <select id="state"><option value="all">All</option><option value="attention">Attention</option><option value="healthy">Healthy</option><option value="unknown">Unknown</option><option value="stale">Stale</option></select></label>
<button id="refresh" type="button">Refresh live status</button>
<p id="feedback" role="status" aria-live="polite"></p>${sections}<script>
const search=document.getElementById('search'),state=document.getElementById('state');
const button=document.getElementById('refresh'),feedback=document.getElementById('feedback');
function filter(){for(const row of document.querySelectorAll('tbody tr'))row.hidden=!(row.textContent.toLowerCase().includes(search.value.toLowerCase())&&(state.value==='all'||row.dataset.state===state.value));}
search.addEventListener('input',filter);state.addEventListener('change',filter);
button.addEventListener('click',async()=>{
button.disabled=true;feedback.textContent='Refreshing through Swamp…';
try{if(location.protocol==='file:')throw new Error();
const action=new URL(location.href);action.search='';action.hash='';
action.pathname=action.pathname.replace(/\\/$/,'')+'/refresh';
const response=await fetch(action,{method:'POST',credentials:'same-origin',redirect:'error',headers:{'X-Report-Action':'refresh'}});
if(!response.ok)throw new Error();const result=await response.json();
if(result.ok!==true)throw new Error();location.reload();
}catch{feedback.textContent='Refresh unavailable. Open the hosted report and try again.';button.disabled=false;}});
</script></body></html>`;
}

/** Server-owned callbacks must use the current caller's scoped Swamp access. */
export interface ReportHost {
  /** Exact canonical report URL, supplied by the operator, never by a request. */
  reportUrl: string;
  /** Authenticate and authorize each read/action; return false to deny. */
  authorize(request: Request, action: "read" | "refresh"): Promise<boolean>;
  /** Read the authorized, versioned Swamp snapshot; no provider calls here. */
  readSnapshot(request: Request): Promise<unknown>;
  /** Run one operator-selected, input-free workflow; resolve only on success. */
  refresh(request: Request): Promise<{ workflowRunId: string }>;
}

/** Return a fetch handler for an existing server; starts no listener or runtime. */
export function createReportHandler(
  host: ReportHost,
): (request: Request) => Promise<Response> {
  const canonical = new URL(host.reportUrl);
  if (
    canonical.protocol !== "https:" || canonical.username ||
    canonical.password || canonical.search || canonical.hash ||
    canonical.pathname.endsWith("/")
  ) throw new Error("Use an exact HTTPS report URL without a trailing slash");
  const refreshPath = canonical.pathname + "/refresh";
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  };
  const json = (status: number, body: unknown) =>
    Response.json(body, { status, headers });
  let refreshing = false;
  return async (request) => {
    const url = new URL(request.url);
    if (url.origin !== canonical.origin) return json(403, { ok: false });
    const read = url.pathname === canonical.pathname &&
      request.method === "GET";
    const refresh = url.pathname === refreshPath && request.method === "POST";
    if (!read && !refresh) return json(404, { ok: false });
    if (
      refresh &&
      (request.headers.get("origin") !== canonical.origin ||
        request.headers.get("X-Report-Action") !== "refresh" ||
        request.headers.has("transfer-encoding") ||
        !["0", null].includes(request.headers.get("content-length")) ||
        request.body !== null || url.search)
    ) return json(403, { ok: false });
    try {
      if (!await host.authorize(request, read ? "read" : "refresh")) {
        return json(403, { ok: false });
      }
      if (read) {
        return new Response(renderReport(await host.readSnapshot(request)), {
          headers: {
            ...headers,
            "content-type": "text/html; charset=utf-8",
            "content-security-policy":
              "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          },
        });
      }
      if (refreshing) return json(409, { ok: false });
      refreshing = true;
      try {
        const result = await host.refresh(request);
        if (
          !result || typeof result.workflowRunId !== "string" ||
          !result.workflowRunId.trim()
        ) throw new Error("Missing workflow evidence");
        return json(200, { ok: true, workflowRunId: result.workflowRunId });
      } finally {
        refreshing = false;
      }
    } catch {
      return json(503, {
        ok: false,
        message: "Report temporarily unavailable",
      });
    }
  };
}

/** Minimal context required to persist the canonical snapshot and HTML artifact. */
interface Context {
  globalArgs: unknown;
  logger: { info(message: string): void };
  writeResource(kind: string, name: string, value: unknown): Promise<unknown>;
  createFileWriter(
    name: string,
    fileName: string,
  ): { writeText(data: string): Promise<unknown> };
}
/** Register a deterministic renderer; hosting and action authorization stay separate. */
export const model = {
  type: "@jpisgeek/dashboard-report-view",
  version: "2026.11.08.1",
  globalArguments: ArgumentsSchema,
  resources: {
    snapshot: {
      description: "Canonical report state.",
      schema: SnapshotSchema,
      lifetime: "30d",
      garbageCollection: 12,
    },
  },
  files: {
    html: {
      description:
        "Rendered interactive report; host as HTML rather than a source viewer.",
      contentType: "text/html",
      lifetime: "30d",
      garbageCollection: 12,
    },
  },
  methods: {
    render: {
      description:
        "Render explicit state into a filterable HTML report and retain its canonical snapshot.",
      arguments: z.object({}),
      execute: async (_args: unknown, ctx: Context) => {
        ctx.logger.info("Rendering report snapshot");
        const { snapshot } = ArgumentsSchema.parse(ctx.globalArgs);
        const html = renderReport(snapshot);
        const state = await ctx.writeResource("snapshot", "snapshot", snapshot);
        const artifact = await ctx.createFileWriter("html", "report.html")
          .writeText(html);
        ctx.logger.info("Report snapshot and HTML stored");
        return { dataHandles: [state, artifact] };
      },
    },
  },
};
