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
const CollectArgsSchema = z.object({
  startingAt: z.iso.datetime().describe("Inclusive RFC 3339 coverage start"),
  endingAt: z.iso.datetime().describe("Exclusive RFC 3339 coverage end"),
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
  amountMinor: z.string().regex(/^\d+(\.\d+)?$/),
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
    totalsMinor: z.array(
      z.object({
        currency: z.string().regex(/^[A-Z]{3}$/),
        amountMinor: z.string().regex(/^\d+(\.\d+)?$/),
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
  while (true) {
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
      if (typeof object.data_refreshed_at === "string") {
        refreshedAt = object.data_refreshed_at;
      }
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
function usageRows(
  pages: Record<string, unknown>[],
  enterprise: boolean,
): UsageRow[] | null {
  const rows: UsageRow[] = [];
  const items = records(pages);
  if (!items) return null;
  for (const item of items) {
    const cache = item.cache_creation && typeof item.cache_creation === "object"
      ? item.cache_creation as Record<string, unknown>
      : {};
    const values = [
      integer(item.uncached_input_tokens),
      integer(cache.ephemeral_5m_input_tokens),
      integer(cache.ephemeral_1h_input_tokens),
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
function costRows(
  pages: Record<string, unknown>[],
  enterprise: boolean,
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
      amountMinor: enterprise ? amount : addDecimal("0", amount),
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
  const costs = costRows(costResult.pages, enterprise);
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
      addDecimal(totals.get(row.currency) ?? "0", row.amountMinor),
    );
  }
  const sum = (key: keyof UsageRow) =>
    (usage ?? []).reduce((n, row) => n + (row[key] as number), 0);
  const snapshot = SnapshotSchema.parse({
    provider: "anthropic",
    accountKind: g.accountKind,
    collectedAt: new Date().toISOString(),
    coverageStart: input.startingAt,
    coverageEnd: input.endingAt,
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
        groupedTop100Cap: enterprise,
      },
    costs: costs === null || costResult.status.state === "unavailable" ||
        costResult.status.state === "unsupported"
      ? null
      : {
        totalsMinor: [...totals].map(([currency, amountMinor]) => ({
          currency,
          amountMinor,
        })),
        breakdowns: costs,
        groupedTop100Cap: enterprise,
      },
  });
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
