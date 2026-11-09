import { z } from "npm:zod@4";
import { State } from "./fleet_contract.ts";
import { renderFleet } from "./fleet_view.ts";
import { ViewOptions } from "./view_options.ts";

/** Callbacks supplied by an existing authenticated host, never by report inputs. */
export interface FleetHost {
  /** Exact HTTPS route owned by the existing host. */
  reportUrl: string;
  /** Optional navigation; reportPath is derived from reportUrl. */
  view?: unknown;
  /** Overall deadline; callbacks must honor the supplied request's signal. */
  timeoutMs?: number;
  /** Authenticate and authorize every request, including repeated refresh clicks. */
  authorize(request: Request, action: "read" | "refresh"): Promise<boolean>;
  /** Read only the caller-authorized, versioned fleet state. */
  readState(request: Request): Promise<unknown>;
  /** Run one fixed, input-free workflow as the authorized caller. */
  refresh(request: Request): Promise<{ workflowRunId: string }>;
}

/** Embed fleet snapshots in an existing host; starts no listener and holds no credential. */
export function createFleetHandler(
  host: FleetHost,
): (request: Request) => Promise<Response> {
  const url = new URL(host.reportUrl);
  if (
    url.protocol !== "https:" || url.username || url.password || url.search ||
    url.hash
  ) throw Error("Use an exact HTTPS report URL");
  const view = ViewOptions.parse({
    ...ViewOptions.parse(host.view ?? {}),
    reportPath: url.pathname,
  });
  const refreshPath = view.reportPath + "/refresh";
  const timeoutMs = z.number().int().min(10).max(120000).parse(
    host.timeoutMs ?? 90000,
  );
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  };
  const json = (status: number, value: unknown) =>
    Response.json(value, { status, headers });
  let pending: Promise<{ workflowRunId: string }> | undefined;
  return async (request: Request) => {
    const target = new URL(request.url);
    if (target.origin !== url.origin) return json(403, { ok: false });
    const read = target.pathname === view.reportPath &&
      request.method === "GET";
    const refresh = target.pathname === refreshPath &&
      request.method === "POST";
    if (!read && !refresh) return json(404, { ok: false });
    if (target.search) return json(403, { ok: false });
    if (
      refresh &&
      (request.headers.get("origin") !== url.origin ||
        request.headers.get("X-Fleet-Action") !== "refresh" ||
        request.headers.has("transfer-encoding") ||
        ![null, "0"].includes(request.headers.get("content-length")) ||
        request.body !== null)
    ) return json(403, { ok: false });
    const abort = new AbortController();
    const signal = AbortSignal.any([request.signal, abort.signal]);
    const active = new Request(request, { signal });
    let rejectAbort: () => void = () => {};
    const interrupted = new Promise<never>((_resolve, reject) => {
      rejectAbort = () => reject(Error("Request interrupted"));
      signal.addEventListener("abort", rejectAbort, { once: true });
      if (signal.aborted) rejectAbort();
    });
    void interrupted.catch(() => {});
    const timer = setTimeout(() => abort.abort(), timeoutMs);
    const bounded = <T>(promise: Promise<T>) =>
      Promise.race([promise, interrupted]);
    try {
      if (signal.aborted) throw Error("Request interrupted");
      if (!await bounded(host.authorize(active, read ? "read" : "refresh"))) {
        return json(403, { ok: false });
      }
      if (read) {
        const state = State.parse(await bounded(host.readState(active)));
        return new Response(renderFleet(state, view), {
          headers: {
            ...headers,
            "content-type": "text/html; charset=utf-8",
            "content-security-policy":
              "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          },
        });
      }
      if (pending) return json(409, { ok: false });
      const job = Promise.resolve().then(() => host.refresh(active));
      pending = job;
      void job.then(() => {
        if (pending === job) pending = undefined;
      }, () => {
        if (pending === job) pending = undefined;
      });
      const result = await bounded(job);
      const workflowRunId = z.string().uuid().parse(result.workflowRunId);
      return json(200, { ok: true, workflowRunId });
    } catch {
      return json(503, {
        ok: false,
        message: "Fleet report temporarily unavailable",
      });
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", rejectAbort);
    }
  };
}
