/** Collect Anthropic Platform or Claude Enterprise organization usage and cost. */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  credential: z.string().min(1).meta({ sensitive: true }).describe(
    "Anthropic Admin, org:admin OAuth, or Enterprise Analytics credential supplied through a vault",
  ),
  accountKind: z.enum(["platform", "enterprise"]).describe(
    "Anthropic product boundary; credential types are not interchangeable",
  ),
  authentication: z.enum(["api-key", "oauth"]).default("api-key").describe(
    "Platform supports Admin API key or org:admin OAuth; Enterprise requires api-key",
  ),
  timeoutMs: z.number().int().positive().default(15_000),
});
// RFC 3339 permits both "…Z" and a numeric offset ("…+02:00"). zod's
// z.iso.datetime() without { offset: true } accepts ONLY the Z spelling, so a
// caller passing a legal offset-form window used to get a raw ZodError out of a
// schema whose own description promised RFC 3339. Accept both spellings here
// and canonicalize to Z in collect() so the stored snapshot has one shape.
const CollectArgsSchema = z.object({
  startingAt: z.iso.datetime({ offset: true }).describe(
    "Inclusive RFC 3339 coverage start",
  ),
  endingAt: z.iso.datetime({ offset: true }).describe(
    "Exclusive RFC 3339 coverage end",
  ),
});
const ErrorKindSchema = z.enum([
  "",
  "unsupported",
  "unauthorized",
  "rate-limited",
  "timeout",
  "unreachable",
  "invalid-response",
  "http-error",
]);
const StatusSchema = z.object({
  state: z.enum(["complete", "partial", "unavailable", "unsupported"]),
  pagesRead: z.number().int().nonnegative(),
  errorKind: ErrorKindSchema,
  message: z.string(),
});
const UsageRowSchema = z.object({
  product: z.string().nullable(),
  model: z.string().nullable(),
  workspaceId: z.string().nullable(),
  uncachedInputTokens: z.number().int().nonnegative(),
  cacheCreation5mTokens: z.number().int().nonnegative(),
  cacheCreation1hTokens: z.number().int().nonnegative(),
  cacheReadTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  requests: z.number().int().nonnegative().nullable(),
});
const CostRowSchema = z.object({
  product: z.string().nullable(),
  model: z.string().nullable(),
  workspaceId: z.string().nullable(),
  description: z.string().nullable(),
  // Named `amount`, not `amountMinor`: the Cost Report returns a decimal string
  // in the currency's MAJOR unit ("1.25" is 1.25 USD). The old name claimed
  // minor units but no code path ever scaled anything, and this repo's other
  // extensions really do use minor units (subscription-metadata carries
  // priceMinor "2500" for a 25.00 plan), so a consumer that trusted the name
  // and divided by 100 underreported spend by 100x. See costRows().
  amount: z.string().regex(/^\d+(\.\d+)?$/),
  currency: z.string().regex(/^[A-Z]{3}$/),
});
const SnapshotSchema = z.object({
  provider: z.literal("anthropic"),
  accountKind: z.enum(["platform", "enterprise"]),
  collectedAt: z.iso.datetime(),
  coverageStart: z.iso.datetime(),
  coverageEnd: z.iso.datetime(),
  dataRefreshedAt: z.iso.datetime().nullable(),
  usageStatus: StatusSchema,
  costStatus: StatusSchema,
  usage: z.object({
    uncachedInputTokens: z.number().int().nonnegative(),
    cacheCreation5mTokens: z.number().int().nonnegative(),
    cacheCreation1hTokens: z.number().int().nonnegative(),
    cacheReadTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    requests: z.number().int().nonnegative().nullable(),
    breakdowns: z.array(UsageRowSchema),
    groupedTop100Cap: z.boolean(),
  }).nullable(),
  costs: z.object({
    totals: z.array(
      z.object({
        currency: z.string().regex(/^[A-Z]{3}$/),
        amount: z.string().regex(/^\d+(\.\d+)?$/),
      }),
    ),
    breakdowns: z.array(CostRowSchema),
    groupedTop100Cap: z.boolean(),
  }).nullable(),
});
type Globals = z.infer<typeof GlobalArgsSchema>;
type Status = z.infer<typeof StatusSchema>;
type UsageRow = z.infer<typeof UsageRowSchema>;
type CostRow = z.infer<typeof CostRowSchema>;
interface Context {
  globalArgs: unknown;
  signal: AbortSignal;
  writeResource(
    spec: string,
    name: string,
    data: z.infer<typeof SnapshotSchema>,
    options?: { tags?: Record<string, string> },
  ): Promise<unknown>;
}
export type Fetcher = typeof fetch;
let fetcher: Fetcher = fetch;
export function setFetcherForTest(value?: Fetcher): void {
  fetcher = value ?? fetch;
}
function message(kind: Status["errorKind"]): string {
  return ({
    "": "",
    unsupported:
      "This Anthropic product does not expose this reporting capability",
    unauthorized: "Anthropic rejected the configured organization credential",
    "rate-limited": "Anthropic rate-limited this observation",
    timeout: "Anthropic did not respond before the timeout",
    unreachable: "Anthropic could not be reached",
    "invalid-response": "Anthropic returned an invalid response",
    "http-error": "Anthropic returned an unsuccessful response",
  })[kind];
}
function statusKind(code: number): Status["errorKind"] {
  return code === 401 || code === 403
    ? "unauthorized"
    : code === 429
    ? "rate-limited"
    : code === 404
    ? "unsupported"
    : "http-error";
}
interface Pages {
  pages: Record<string, unknown>[];
  status: Status;
  refreshedAt: string | null;
}
/**
 * Ceilings on one readPages() walk.
 *
 * timeoutMs bounds a single HTTP request and its AbortSignal is rebuilt on
 * every iteration, so it never bounded the walk as a whole — an operator who
 * set timeoutMs: 15000 could still be inside one collect() call hours later.
 * The only termination guard used to be the repeated-cursor Set, which stops a
 * paginator that loops but not one that keeps minting fresh cursors. These two
 * ceilings make the loop terminate on its own and report what it did read as
 * partial, rather than accumulating pages in memory without bound.
 */
const MAX_PAGES = 500;
const MAX_ELAPSED_MS = 300_000;
/**
 * RFC 3339 shape, both spellings of the zone. See the CollectArgsSchema note:
 * the snapshot stores z.iso.datetime(), which is Z-only.
 */
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;
/**
 * data_refreshed_at used to be copied into the snapshot on nothing more than
 * `typeof === "string"`. Anthropic documents it as RFC 3339, which permits
 * "2026-08-29T10:00:00+00:00" — a value SnapshotSchema rejects — so a legal
 * offset-form timestamp threw a ZodError at the very end of a wholly successful
 * two-endpoint collection and nothing was written at all. Canonicalize to UTC
 * (same instant, Z spelling) and drop anything that is not a timestamp.
 */
function timestamp(value: unknown): string | null {
  if (typeof value !== "string" || !RFC3339.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}
async function readPages(
  g: Globals,
  path: string,
  params: URLSearchParams,
  caller: AbortSignal,
): Promise<Pages> {
  const pages: Record<string, unknown>[] = [];
  const cursors = new Set<string>();
  let page: string | null = null;
  let refreshedAt: string | null = null;
  const startedAt = Date.now();
  while (true) {
    if (pages.length >= MAX_PAGES || Date.now() - startedAt >= MAX_ELAPSED_MS) {
      const capped = pages.length >= MAX_PAGES;
      return {
        pages,
        refreshedAt,
        status: {
          state: pages.length ? "partial" : "unavailable",
          pagesRead: pages.length,
          errorKind: capped ? "" : "timeout",
          message: capped
            ? `Stopped after ${MAX_PAGES} pages while Anthropic still reported more results`
            : message("timeout"),
        },
      };
    }
    const query = new URLSearchParams(params);
    if (page) query.set("page", page);
    const timeout = AbortSignal.timeout(g.timeoutMs);
    const signal = AbortSignal.any([caller, timeout]);
    const headers: Record<string, string> = {
      "anthropic-version": "2023-06-01",
    };
    if (g.authentication === "oauth") {
      headers.authorization = `Bearer ${g.credential}`;
    } else headers["x-api-key"] = g.credential;
    try {
      const response = await fetcher(
        `https://api.anthropic.com${path}?${query}`,
        { headers, signal, redirect: "error" },
      );
      if (!response.ok) {
        const kind = statusKind(response.status);
        return {
          pages,
          refreshedAt,
          status: {
            state: pages.length
              ? "partial"
              : kind === "unsupported"
              ? "unsupported"
              : "unavailable",
            pagesRead: pages.length,
            errorKind: kind,
            message: message(kind),
          },
        };
      }
      const body: unknown = await response.json();
      if (
        !body || typeof body !== "object" ||
        !Array.isArray((body as Record<string, unknown>).data)
      ) {
        return {
          pages,
          refreshedAt,
          status: {
            state: pages.length ? "partial" : "unavailable",
            pagesRead: pages.length,
            errorKind: "invalid-response",
            message: message("invalid-response"),
          },
        };
      }
      const object = body as Record<string, unknown>;
      pages.push(object);
      const refreshed = timestamp(object.data_refreshed_at);
      if (refreshed) refreshedAt = refreshed;
      if (object.has_more !== true) {
        return {
          pages,
          refreshedAt,
          status: {
            state: "complete",
            pagesRead: pages.length,
            errorKind: "",
            message: "",
          },
        };
      }
      const next = typeof object.next_page === "string"
        ? object.next_page
        : null;
      if (!next || cursors.has(next)) {
        return {
          pages,
          refreshedAt,
          status: {
            state: "partial",
            pagesRead: pages.length,
            errorKind: "invalid-response",
            message: message("invalid-response"),
          },
        };
      }
      cursors.add(next);
      page = next;
    } catch (error) {
      if (caller.aborted) throw error;
      const kind = timeout.aborted
        ? "timeout"
        : error instanceof SyntaxError
        ? "invalid-response"
        : "unreachable";
      return {
        pages,
        refreshedAt,
        status: {
          state: pages.length ? "partial" : "unavailable",
          pagesRead: pages.length,
          errorKind: kind,
          message: message(kind),
        },
      };
    }
  }
}
function records(
  pages: Record<string, unknown>[],
): Record<string, unknown>[] | null {
  const output: Record<string, unknown>[] = [];
  for (const page of pages) {
    if (!Array.isArray(page.data)) return null;
    for (const bucket of page.data) {
      if (!bucket || typeof bucket !== "object") return null;
      const results = (bucket as Record<string, unknown>).results;
      if (!Array.isArray(results)) return null;
      for (const item of results) {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          return null;
        }
        output.push(item as Record<string, unknown>);
      }
    }
  }
  return output;
}
function integer(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0
    ? value
    : null;
}
/**
 * An absent cache sub-field means "no cache activity in this grouping", which
 * is 0. A present but wrong-typed one is still rejected — this tolerates
 * absence, it does not let a malformed dimension become a reassuring zero.
 */
function optionalInteger(value: unknown): number | null {
  return value === undefined ? 0 : integer(value);
}
/**
 * Anthropic's grouped reports return at most 100 groups per time bucket, so a
 * bucket that comes back exactly full is the only evidence available that
 * groups were dropped. groupedTop100Cap used to be `accountKind === "enterprise"`
 * — true for every Enterprise snapshot regardless of the response — which made
 * the dashboard mark every Enterprise section partial, downgrade every metric
 * to unknown confidence, and raise a standing warning exception on a complete
 * two-group result. A warning that is always on teaches operators to ignore it.
 *
 * Kept Enterprise-only at the call site: the top-100 cap is what Anthropic
 * documents for the Analytics grouped reports, and inventing the same claim for
 * Platform would be guessing.
 */
const GROUP_CAP = 100;
function bucketAtCap(pages: Record<string, unknown>[]): boolean {
  for (const page of pages) {
    if (!Array.isArray(page.data)) continue;
    for (const bucket of page.data) {
      if (!bucket || typeof bucket !== "object") continue;
      const results = (bucket as Record<string, unknown>).results;
      if (Array.isArray(results) && results.length >= GROUP_CAP) return true;
    }
  }
  return false;
}
function usageRows(
  pages: Record<string, unknown>[],
  enterprise: boolean,
): UsageRow[] | null {
  const rows: UsageRow[] = [];
  const items = records(pages);
  if (!items) return null;
  for (const item of items) {
    // The old `: {}` fallback looked like it tolerated a missing cache_creation
    // object but was self-defeating: integer(undefined) returned null, and one
    // such row anywhere in the paged result nulled usage for the whole window
    // and reported "Anthropic returned an invalid response". A grouping with no
    // 1-hour-cache activity may legitimately omit the sub-field rather than
    // send 0. Absence is now genuinely 0; a present-but-wrong-typed
    // cache_creation, or sub-field, still rejects the whole window.
    if (
      item.cache_creation !== undefined && item.cache_creation !== null &&
      (typeof item.cache_creation !== "object" ||
        Array.isArray(item.cache_creation))
    ) return null;
    const cache = (item.cache_creation ?? {}) as Record<string, unknown>;
    const values = [
      integer(item.uncached_input_tokens),
      optionalInteger(cache.ephemeral_5m_input_tokens),
      optionalInteger(cache.ephemeral_1h_input_tokens),
      integer(item.cache_read_input_tokens),
      integer(item.output_tokens),
    ];
    if (values.some((v) => v === null)) return null;
    const requests = enterprise ? integer(item.requests) : null;
    if (enterprise && requests === null) return null;
    rows.push({
      product: typeof item.product === "string" ? item.product : null,
      model: typeof item.model === "string" ? item.model : null,
      workspaceId: typeof item.workspace_id === "string"
        ? item.workspace_id
        : null,
      uncachedInputTokens: values[0]!,
      cacheCreation5mTokens: values[1]!,
      cacheCreation1hTokens: values[2]!,
      cacheReadTokens: values[3]!,
      outputTokens: values[4]!,
      requests,
    });
  }
  return rows;
}
function decimal(value: unknown): string | null {
  return typeof value === "string" && /^\d+(\.\d+)?$/.test(value)
    ? value
    : null;
}
function addDecimal(a: string, b: string): string {
  const places = Math.max(
    (a.split(".")[1] ?? "").length,
    (b.split(".")[1] ?? "").length,
  );
  const scale = 10n ** BigInt(places);
  const parse = (v: string) => {
    const [whole, fraction = ""] = v.split(".");
    return BigInt(whole) * scale + BigInt(fraction.padEnd(places, "0"));
  };
  const sum = parse(a) + parse(b);
  const whole = sum / scale;
  const fraction = (sum % scale).toString().padStart(places, "0").replace(
    /0+$/,
    "",
  );
  return fraction ? `${whole}.${fraction}` : whole.toString();
}
// No `enterprise` parameter any more: cost amounts are read and stored
// identically for both account kinds. See the amount comment below.
function costRows(
  pages: Record<string, unknown>[],
): CostRow[] | null {
  const rows: CostRow[] = [];
  const items = records(pages);
  if (!items) return null;
  for (const item of items) {
    const amount = decimal(item.amount);
    const currency = item.currency;
    if (
      !amount || typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)
    ) return null;
    rows.push({
      product: typeof item.product === "string" ? item.product : null,
      model: typeof item.model === "string" ? item.model : null,
      workspaceId: typeof item.workspace_id === "string"
        ? item.workspace_id
        : null,
      description: typeof item.description === "string"
        ? item.description
        : null,
      // One spelling for both account kinds. The old ternary
      // (`enterprise ? amount : addDecimal("0", amount)`) performed no unit
      // conversion in either branch — it only chose whether to normalize the
      // string — so the same value was stored differently depending on account
      // kind, and "125.00" survived in an Enterprise breakdown next to a "125"
      // total. Normalize both so breakdowns compare equal to the totals that
      // addDecimal produces downstream.
      amount: addDecimal("0", amount),
      currency,
    });
  }
  return rows;
}
async function collect(args: z.infer<typeof CollectArgsSchema>, ctx: Context) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const input = CollectArgsSchema.parse(args);
  if (Date.parse(input.endingAt) <= Date.parse(input.startingAt)) {
    throw new Error("endingAt must be after startingAt");
  }
  if (g.accountKind === "enterprise" && g.authentication === "oauth") {
    throw new Error(
      "Claude Enterprise Analytics requires authentication=api-key",
    );
  }
  const params = new URLSearchParams({
    starting_at: input.startingAt,
    ending_at: input.endingAt,
    bucket_width: "1d",
  });
  const enterprise = g.accountKind === "enterprise";
  const usageParams = new URLSearchParams(params);
  const costParams = new URLSearchParams(params);
  for (
    const value of enterprise ? ["product", "model"] : ["workspace_id", "model"]
  ) usageParams.append("group_by[]", value);
  for (
    const value of enterprise
      ? ["product", "model", "cost_type"]
      : ["workspace_id", "description"]
  ) costParams.append("group_by[]", value);
  const prefix = enterprise
    ? "/v1/organizations/analytics"
    : "/v1/organizations";
  const [usageResult, costResult] = await Promise.all([
    readPages(
      g,
      `${prefix}/${enterprise ? "usage_report" : "usage_report/messages"}`,
      usageParams,
      ctx.signal,
    ),
    readPages(g, `${prefix}/cost_report`, costParams, ctx.signal),
  ]);
  const usage = usageRows(usageResult.pages, enterprise);
  const costs = costRows(costResult.pages);
  if (usage === null) {
    usageResult.status = {
      state: usageResult.pages.length ? "partial" : "unavailable",
      pagesRead: usageResult.pages.length,
      errorKind: "invalid-response",
      message: message("invalid-response"),
    };
  }
  if (costs === null) {
    costResult.status = {
      state: costResult.pages.length ? "partial" : "unavailable",
      pagesRead: costResult.pages.length,
      errorKind: "invalid-response",
      message: message("invalid-response"),
    };
  }
  const totals = new Map<string, string>();
  for (const row of costs ?? []) {
    totals.set(
      row.currency,
      addDecimal(totals.get(row.currency) ?? "0", row.amount),
    );
  }
  const sum = (key: keyof UsageRow) =>
    (usage ?? []).reduce((n, row) => n + (row[key] as number), 0);
  // The window may arrive in either RFC 3339 spelling (see CollectArgsSchema);
  // the snapshot stores the canonical Z form so consumers see one shape and the
  // strict z.iso.datetime() fields below cannot reject our own input.
  const coverageStart = new Date(input.startingAt).toISOString();
  const coverageEnd = new Date(input.endingAt).toISOString();
  const candidate = {
    provider: "anthropic",
    accountKind: g.accountKind,
    collectedAt: new Date().toISOString(),
    coverageStart,
    coverageEnd,
    dataRefreshedAt: usageResult.refreshedAt ?? costResult.refreshedAt,
    usageStatus: usageResult.status,
    costStatus: costResult.status,
    usage: usage === null || usageResult.status.state === "unavailable" ||
        usageResult.status.state === "unsupported"
      ? null
      : {
        uncachedInputTokens: sum("uncachedInputTokens"),
        cacheCreation5mTokens: sum("cacheCreation5mTokens"),
        cacheCreation1hTokens: sum("cacheCreation1hTokens"),
        cacheReadTokens: sum("cacheReadTokens"),
        outputTokens: sum("outputTokens"),
        requests: enterprise ? sum("requests") : null,
        breakdowns: usage,
        groupedTop100Cap: enterprise && bucketAtCap(usageResult.pages),
      },
    costs: costs === null || costResult.status.state === "unavailable" ||
        costResult.status.state === "unsupported"
      ? null
      : {
        totals: [...totals].map(([currency, amount]) => ({
          currency,
          amount,
        })),
        breakdowns: costs,
        groupedTop100Cap: enterprise && bucketAtCap(costResult.pages),
      },
  };
  // Everything above this line is fail-soft: an unusable response degrades to a
  // status and usage/costs go null, never to a reassuring zero. This parse was
  // the single fail-hard step. A late schema violation — a token count above
  // Number.MAX_SAFE_INTEGER, which integer() accepts but z.number().int()
  // rejects, or a per-row sum that crosses it — threw an uncaught ZodError
  // after both paginated fetches had already succeeded, and nothing at all was
  // written. Degrade to the same invalid-response shape the rest of collect()
  // uses so the operator gets a snapshot that says so.
  let snapshot: z.infer<typeof SnapshotSchema>;
  const parsed = SnapshotSchema.safeParse(candidate);
  if (parsed.success) {
    snapshot = parsed.data;
  } else {
    const degrade = (result: Pages): Status => ({
      state: result.pages.length ? "partial" : "unavailable",
      pagesRead: result.pages.length,
      errorKind: "invalid-response",
      message: message("invalid-response"),
    });
    snapshot = SnapshotSchema.parse({
      provider: "anthropic",
      accountKind: g.accountKind,
      collectedAt: new Date().toISOString(),
      coverageStart,
      coverageEnd,
      dataRefreshedAt: null,
      usageStatus: degrade(usageResult),
      costStatus: degrade(costResult),
      usage: null,
      costs: null,
    });
  }
  const handle = await ctx.writeResource(
    "snapshot",
    "organization-usage",
    snapshot,
    {
      tags: {
        provider: "anthropic",
        accountKind: g.accountKind,
        usage: snapshot.usageStatus.state,
        costs: snapshot.costStatus.state,
      },
    },
  );
  return { dataHandles: [handle] };
}
export const model = {
  type: "@jpisgeek/anthropic-usage",
  version: "2026.08.25.2",
  globalArguments: GlobalArgsSchema,
  resources: {
    snapshot: {
      description:
        "Anthropic organization usage, authoritative cost, product capability, refresh, and coverage states.",
      schema: SnapshotSchema,
      lifetime: "90d" as const,
      garbageCollection: 90,
    },
  },
  methods: {
    collect: {
      description:
        "Collect independently paginated usage and cost for an explicit Anthropic product and window.",
      arguments: CollectArgsSchema,
      execute: collect,
    },
  },
};
