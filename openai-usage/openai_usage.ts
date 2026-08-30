/** Collect OpenAI organization completion usage and billed costs. */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  apiKey: z.string().min(1).meta({ sensitive: true }).describe(
    "OpenAI Admin API key supplied through a vault expression",
  ),
  timeoutMs: z.number().int().positive().default(15_000),
});

const CollectArgsSchema = z.object({
  startTime: z.number().int().nonnegative().describe(
    "Inclusive coverage start as Unix seconds",
  ),
  endTime: z.number().int().positive().optional().describe(
    "Exclusive coverage end as Unix seconds; defaults to collection time",
  ),
});

const ErrorKindSchema = z.enum([
  "",
  "unauthorized",
  "rate-limited",
  "timeout",
  "unreachable",
  "invalid-response",
  "http-error",
]);

const DimensionStatusSchema = z.object({
  state: z.enum(["complete", "partial", "unavailable"]),
  pagesRead: z.number().int().nonnegative(),
  errorKind: ErrorKindSchema,
  message: z.string(),
});

const UsageBreakdownSchema = z.object({
  projectId: z.string().nullable(),
  model: z.string().nullable(),
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  cachedInputTokens: z.number().int().nonnegative(),
  requests: z.number().int().nonnegative(),
});

const CostBreakdownSchema = z.object({
  projectId: z.string().nullable(),
  lineItem: z.string().nullable(),
  value: z.number().nonnegative().finite(),
  currency: z.string().regex(/^[a-z]{3}$/),
});

const SnapshotSchema = z.object({
  provider: z.literal("openai"),
  collectedAt: z.iso.datetime(),
  coverageStart: z.iso.datetime(),
  coverageEnd: z.iso.datetime(),
  usageStatus: DimensionStatusSchema,
  costStatus: DimensionStatusSchema,
  usage: z.object({
    inputTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    cachedInputTokens: z.number().int().nonnegative(),
    requests: z.number().int().nonnegative(),
    breakdowns: z.array(UsageBreakdownSchema),
  }).nullable(),
  costs: z.object({
    totals: z.array(z.object({
      currency: z.string().regex(/^[a-z]{3}$/),
      value: z.number().nonnegative().finite(),
    })),
    breakdowns: z.array(CostBreakdownSchema),
  }).nullable(),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;
type DimensionStatus = z.infer<typeof DimensionStatusSchema>;
type UsageBreakdown = z.infer<typeof UsageBreakdownSchema>;
type CostBreakdown = z.infer<typeof CostBreakdownSchema>;

interface ModelContext {
  globalArgs: unknown;
  signal: AbortSignal;
  writeResource(
    specName: string,
    name: string,
    data: z.infer<typeof SnapshotSchema>,
    options?: { tags?: Record<string, string> },
  ): Promise<unknown>;
}

export type Fetcher = typeof fetch;
let fetcher: Fetcher = fetch;

/** Test seam; production uses the platform fetch implementation. */
export function setFetcherForTest(value?: Fetcher): void {
  fetcher = value ?? fetch;
}

function classifyStatus(status: number): DimensionStatus["errorKind"] {
  if (status === 401 || status === 403) return "unauthorized";
  if (status === 429) return "rate-limited";
  return "http-error";
}

function safeMessage(kind: DimensionStatus["errorKind"]): string {
  const messages: Record<DimensionStatus["errorKind"], string> = {
    "": "",
    unauthorized: "OpenAI rejected the configured Admin API credential",
    "rate-limited": "OpenAI rate-limited this observation",
    timeout: "OpenAI did not respond before the timeout",
    unreachable: "OpenAI could not be reached",
    "invalid-response": "OpenAI returned an invalid response",
    "http-error": "OpenAI returned an unsuccessful response",
  };
  return messages[kind];
}

interface PageResult {
  pages: Record<string, unknown>[];
  status: DimensionStatus;
}

async function readPages(
  g: GlobalArgs,
  path: string,
  params: URLSearchParams,
  callerSignal: AbortSignal,
): Promise<PageResult> {
  const pages: Record<string, unknown>[] = [];
  let page: string | null = null;
  const cursors = new Set<string>();
  while (true) {
    const query = new URLSearchParams(params);
    if (page) query.set("page", page);
    const timeout = AbortSignal.timeout(g.timeoutMs);
    const signal = AbortSignal.any([callerSignal, timeout]);
    try {
      const response = await fetcher(`https://api.openai.com${path}?${query}`, {
        headers: { Authorization: `Bearer ${g.apiKey}` },
        signal,
      });
      if (!response.ok) {
        const kind = classifyStatus(response.status);
        return {
          pages,
          status: {
            state: pages.length ? "partial" : "unavailable",
            pagesRead: pages.length,
            errorKind: kind,
            message: safeMessage(kind),
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
          status: {
            state: pages.length ? "partial" : "unavailable",
            pagesRead: pages.length,
            errorKind: "invalid-response",
            message: safeMessage("invalid-response"),
          },
        };
      }
      const object = body as Record<string, unknown>;
      pages.push(object);
      const hasMore = object.has_more === true;
      const next = typeof object.next_page === "string"
        ? object.next_page
        : null;
      if (!hasMore) {
        return {
          pages,
          status: {
            state: "complete",
            pagesRead: pages.length,
            errorKind: "",
            message: "",
          },
        };
      }
      if (!next || cursors.has(next)) {
        return {
          pages,
          status: {
            state: "partial",
            pagesRead: pages.length,
            errorKind: "invalid-response",
            message: safeMessage("invalid-response"),
          },
        };
      }
      cursors.add(next);
      page = next;
    } catch (error) {
      if (callerSignal.aborted) throw error;
      const kind = timeout.aborted
        ? "timeout"
        : error instanceof SyntaxError
        ? "invalid-response"
        : "unreachable";
      return {
        pages,
        status: {
          state: pages.length ? "partial" : "unavailable",
          pagesRead: pages.length,
          errorKind: kind,
          message: safeMessage(kind),
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
      if (!bucket || typeof bucket !== "object" || Array.isArray(bucket)) {
        return null;
      }
      const results = (bucket as Record<string, unknown>).results;
      if (!Array.isArray(results)) return null;
      for (const result of results) {
        if (!result || typeof result !== "object" || Array.isArray(result)) {
          return null;
        }
        output.push(result as Record<string, unknown>);
      }
    }
  }
  return output;
}

/**
 * Only accepts values SnapshotSchema will also accept. Number.isInteger() is
 * not a tight enough guard: it says yes to 1e21, which zod's .int() rejects
 * because it sits above MAX_SAFE_INTEGER. While the two disagreed, an absurd
 * token count passed this check, reached SnapshotSchema.parse at the end of
 * collect(), and threw a ZodError out of the method instead of degrading the
 * dimension the way every other malformed-input path in this file does.
 */
function nonnegativeInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;
}

/**
 * Reads a counter OpenAI's contract marks optional. UsageCompletionsResult
 * requires only object, input_tokens, output_tokens and num_model_requests;
 * input_cached_tokens is simply absent when no caching applied. Requiring it
 * blacked out the entire usage dimension — usage written as null, the status
 * overwritten to invalid-response — for a response the published contract
 * explicitly permits, so an absent counter now reads as the zero it means. A
 * counter that is present but wrongly typed is still a protocol violation and
 * still invalidates the dimension.
 */
function optionalCounter(value: unknown): number | null {
  if (value === undefined || value === null) return 0;
  return nonnegativeInteger(value);
}

function usageFrom(pages: Record<string, unknown>[]): UsageBreakdown[] | null {
  const output: UsageBreakdown[] = [];
  const items = records(pages);
  if (!items) return null;
  for (const item of items) {
    const input = nonnegativeInteger(item.input_tokens);
    const outputTokens = nonnegativeInteger(item.output_tokens);
    const cached = optionalCounter(item.input_cached_tokens);
    const requests = nonnegativeInteger(item.num_model_requests);
    if ([input, outputTokens, cached, requests].some((v) => v === null)) {
      return null;
    }
    output.push({
      projectId: typeof item.project_id === "string" ? item.project_id : null,
      model: typeof item.model === "string" ? item.model : null,
      inputTokens: input!,
      outputTokens: outputTokens!,
      cachedInputTokens: cached!,
      requests: requests!,
    });
  }
  return output;
}

interface CostRows {
  rows: CostBreakdown[];
  /** Legal rows carrying no attributable amount; see costsFrom. */
  dropped: number;
}

/**
 * OpenAI's CostsResult contract requires only `object`. The `amount` wrapper,
 * and `value` and `currency` inside it, are all optional. This used to return
 * null — blacking out the whole cost dimension, costs written as null — the
 * moment a single row on a single page omitted any one of them.
 *
 * Absence is now tolerated, garbage is not. A row with no amount carries no
 * spend attributable to a currency, so it is dropped and counted, and collect()
 * downgrades the dimension to partial so the drop stays visible instead of
 * quietly lowering the total. A field that is present but wrongly typed,
 * negative, non-finite, or not a lowercase ISO-4217 code is a real protocol
 * violation and still invalidates the dimension.
 */
function costsFrom(pages: Record<string, unknown>[]): CostRows | null {
  const rows: CostBreakdown[] = [];
  let dropped = 0;
  const items = records(pages);
  if (!items) return null;
  for (const item of items) {
    const amount = item.amount;
    if (amount === undefined || amount === null) {
      dropped++;
      continue;
    }
    if (typeof amount !== "object" || Array.isArray(amount)) return null;
    const value = (amount as Record<string, unknown>).value;
    const currency = (amount as Record<string, unknown>).currency;
    if (
      value === undefined || value === null ||
      currency === undefined || currency === null
    ) {
      dropped++;
      continue;
    }
    if (
      typeof value !== "number" || !Number.isFinite(value) || value < 0 ||
      typeof currency !== "string" || !/^[a-z]{3}$/.test(currency)
    ) return null;
    rows.push({
      projectId: typeof item.project_id === "string" ? item.project_id : null,
      lineItem: typeof item.line_item === "string" ? item.line_item : null,
      value,
      currency,
    });
  }
  return { rows, dropped };
}

async function collect(
  args: z.infer<typeof CollectArgsSchema>,
  ctx: ModelContext,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  const parsed = CollectArgsSchema.parse(args);
  const endTime = parsed.endTime ?? Math.floor(Date.now() / 1000);
  if (endTime <= parsed.startTime) {
    throw new Error("endTime must be after startTime");
  }
  // Date#toISOString() throws a bare "RangeError: Invalid time value" past
  // ±8.64e12 seconds, and CollectArgsSchema accepts any nonnegative integer.
  // Reject the window here so the caller gets a message naming the argument.
  const coverageStart = new Date(parsed.startTime * 1000);
  const coverageEnd = new Date(endTime * 1000);
  if (
    Number.isNaN(coverageStart.getTime()) || Number.isNaN(coverageEnd.getTime())
  ) {
    throw new Error("startTime and endTime must be representable Unix seconds");
  }
  const common = new URLSearchParams({
    start_time: String(parsed.startTime),
    end_time: String(endTime),
    bucket_width: "1d",
  });
  const usageParams = new URLSearchParams(common);
  usageParams.append("group_by", "project_id");
  usageParams.append("group_by", "model");
  const costParams = new URLSearchParams(common);
  costParams.append("group_by", "project_id");
  costParams.append("group_by", "line_item");
  const [usageResult, costResult] = await Promise.all([
    readPages(g, "/v1/organization/usage/completions", usageParams, ctx.signal),
    readPages(g, "/v1/organization/costs", costParams, ctx.signal),
  ]);
  let usageRows = usageFrom(usageResult.pages);
  const costData = costsFrom(costResult.pages);
  let costRows = costData?.rows ?? null;

  // Row-level guards do not survive addition. A page of individually legal rows
  // can sum past MAX_SAFE_INTEGER (tokens, rejected by the schema's .int()) or
  // to Infinity (two costs near Number.MAX_VALUE, rejected by .finite()). The
  // parse below used to be unguarded, so an overflow in one dimension threw a
  // ZodError out of collect() and discarded the *other* dimension's perfectly
  // good result along with it. An overflowing total now degrades only its own
  // dimension, exactly like any other unusable payload.
  let usageTotals: {
    inputTokens: number;
    outputTokens: number;
    cachedInputTokens: number;
    requests: number;
  } | null = null;
  if (usageRows !== null) {
    usageTotals = {
      inputTokens: usageRows.reduce((n, r) => n + r.inputTokens, 0),
      outputTokens: usageRows.reduce((n, r) => n + r.outputTokens, 0),
      cachedInputTokens: usageRows.reduce((n, r) => n + r.cachedInputTokens, 0),
      requests: usageRows.reduce((n, r) => n + r.requests, 0),
    };
    if (!Object.values(usageTotals).every(Number.isSafeInteger)) {
      usageRows = null;
      usageTotals = null;
    }
  }
  const totals = new Map<string, number>();
  if (costRows !== null) {
    for (const row of costRows) {
      totals.set(row.currency, (totals.get(row.currency) ?? 0) + row.value);
    }
    if (![...totals.values()].every(Number.isFinite)) {
      costRows = null;
      totals.clear();
    }
  }

  if (usageRows === null) {
    usageResult.status = {
      state: usageResult.pages.length ? "partial" : "unavailable",
      pagesRead: usageResult.pages.length,
      errorKind: "invalid-response",
      message: safeMessage("invalid-response"),
    };
  }
  if (costRows === null) {
    costResult.status = {
      state: costResult.pages.length ? "partial" : "unavailable",
      pagesRead: costResult.pages.length,
      errorKind: "invalid-response",
      message: safeMessage("invalid-response"),
    };
  } else if (
    costData !== null && costData.dropped > 0 &&
    costResult.status.state === "complete"
  ) {
    // Dropped rows are contract-legal but unattributable, not a protocol error,
    // so the dimension stays usable and only loses its claim to completeness.
    // errorKind stays empty because nothing about the response was invalid;
    // the dashboard renders a partial section from the message alone.
    costResult.status = {
      state: "partial",
      pagesRead: costResult.pages.length,
      errorKind: "",
      message: `OpenAI omitted the billed amount on ${costData.dropped} cost ${
        costData.dropped === 1 ? "row" : "rows"
      }`,
    };
  }
  const candidate = {
    provider: "openai",
    collectedAt: new Date().toISOString(),
    coverageStart: coverageStart.toISOString(),
    coverageEnd: coverageEnd.toISOString(),
    usageStatus: usageResult.status,
    costStatus: costResult.status,
    usage: usageRows === null || usageTotals === null ||
        usageResult.status.state === "unavailable"
      ? null
      : { ...usageTotals, breakdowns: usageRows },
    costs: costRows === null || costResult.status.state === "unavailable"
      ? null
      : {
        totals: [...totals].map(([currency, value]) => ({ currency, value })),
        breakdowns: costRows,
      },
  };
  // Last-resort net under the guards above. Every other malformed-input path in
  // this file degrades to a status; a throw here would reject the whole run and
  // lose both dimensions, so an unanticipated schema violation degrades to the
  // same explicit unavailable state rather than escaping collect().
  const validated = SnapshotSchema.safeParse(candidate);
  const snapshot = validated.success ? validated.data : SnapshotSchema.parse({
    provider: "openai",
    collectedAt: new Date().toISOString(),
    coverageStart: coverageStart.toISOString(),
    coverageEnd: coverageEnd.toISOString(),
    usageStatus: {
      state: "unavailable",
      pagesRead: usageResult.pages.length,
      errorKind: "invalid-response",
      message: safeMessage("invalid-response"),
    },
    costStatus: {
      state: "unavailable",
      pagesRead: costResult.pages.length,
      errorKind: "invalid-response",
      message: safeMessage("invalid-response"),
    },
    usage: null,
    costs: null,
  });
  const handle = await ctx.writeResource(
    "snapshot",
    "organization-usage",
    snapshot,
    {
      tags: {
        provider: "openai",
        usage: snapshot.usageStatus.state,
        costs: snapshot.costStatus.state,
      },
    },
  );
  return { dataHandles: [handle] };
}

export const model = {
  type: "@jpisgeek/openai-usage",
  version: "2026.08.25.2",
  globalArguments: GlobalArgsSchema,
  resources: {
    snapshot: {
      description:
        "Sanitized OpenAI organization usage, billed cost, coverage, and independent availability states.",
      schema: SnapshotSchema,
      lifetime: "90d" as const,
      garbageCollection: 90,
    },
  },
  methods: {
    collect: {
      description:
        "Collect paginated completion usage and billed costs for an explicit UTC window.",
      arguments: CollectArgsSchema,
      execute: collect,
    },
  },
};
