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
  inputAudioTokens: z.number().int().nonnegative(),
  outputAudioTokens: z.number().int().nonnegative(),
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
    inputAudioTokens: z.number().int().nonnegative(),
    outputAudioTokens: z.number().int().nonnegative(),
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
  /**
   * Transport override, supplied per call by the caller that already holds the
   * credential. Absent in production, where the platform `fetch` is used.
   *
   * This replaced an exported `setFetcherForTest` that mutated module-level
   * state. That seam shipped in the published package, so ANY importer could
   * install a transport and receive the live Authorization header of a
   * legitimate collection running in the same process -- defeating the fixed
   * host, HTTPS and no-redirect guarantees this file otherwise makes. Injection
   * per call cannot do that: a caller can only route its own request, using a
   * key it already supplied in globalArgs.
   */
  fetch?: typeof fetch;
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

/**
 * Endpoint-specific result rows, validated at the boundary where the bytes
 * arrive rather than field by field further in.
 *
 * These used to be `z.record(z.string(), z.unknown())` inside a passthrough
 * bucket: every row was an arbitrary bag, the `object` discriminator that says
 * which shape a row even claims to be went unchecked, and any field OpenAI
 * sent survived into the code that aggregates. Nothing downstream could tell a
 * completions result from a costs result, or from an unrelated object that
 * happened to carry an `input_tokens` key.
 *
 * `strictObject` is the point of the fix, not an accident of it: a row is
 * accepted only if every one of its keys is a field this version models and
 * has validated. An unmodelled key is an unvalidated key, so the row does not
 * parse and the dimension degrades — the same treatment every other
 * off-contract payload in this file gets, and never a silent partial total.
 *
 * The optional fields below are optional because OpenAI's contract makes them
 * so; requiring them would black out a legitimate response. `.optional()` and
 * `.nullable()` are deliberately not interchangeable here. An absent key is
 * the contract's own "no value". An explicit null is a value OpenAI chose to
 * send, so it is accepted only on the group-by identifiers OpenAI genuinely
 * nulls out on an ungrouped row — the same dimensions SnapshotSchema declares
 * nullable — and rejected on every counter, which the contract types as a
 * plain integer.
 *
 * `.int()` also draws the upper bound: it rejects 1e21, which Number.isInteger
 * would have accepted, so an absurd token count is refused here instead of
 * reaching SnapshotSchema.parse at the end of collect() and throwing a ZodError
 * out of the method — which used to discard the other, healthy dimension too.
 */
const UsageResultSchema = z.strictObject({
  object: z.literal("organization.usage.completions.result"),
  input_tokens: z.number().int().nonnegative(),
  output_tokens: z.number().int().nonnegative(),
  num_model_requests: z.number().int().nonnegative(),
  input_cached_tokens: z.number().int().nonnegative().optional(),
  input_audio_tokens: z.number().int().nonnegative().optional(),
  output_audio_tokens: z.number().int().nonnegative().optional(),
  project_id: z.string().nullable().optional(),
  user_id: z.string().nullable().optional(),
  api_key_id: z.string().nullable().optional(),
  model: z.string().nullable().optional(),
  batch: z.boolean().nullable().optional(),
  service_tier: z.string().nullable().optional(),
});

/**
 * CostsResult requires only `object`. The `amount` wrapper and both fields
 * inside it are optional, and a row can legally carry no attributable amount
 * at all — costsFrom() drops and counts those rather than inventing a zero.
 *
 * The value bounds live here now, at the boundary, so a negative or non-finite
 * amount is refused before anything sums it. `currency` is pinned to the
 * lowercase ISO-4217 form SnapshotSchema stores, so a row cannot introduce a
 * currency key the snapshot schema would later reject and turn into a throw.
 */
const CostResultSchema = z.strictObject({
  object: z.literal("organization.costs.result"),
  amount: z.strictObject({
    value: z.number().nonnegative().finite().optional(),
    currency: z.string().regex(/^[a-z]{3}$/).optional(),
  }).optional(),
  line_item: z.string().nullable().optional(),
  project_id: z.string().nullable().optional(),
  organization_id: z.string().nullable().optional(),
});

type UsageResult = z.infer<typeof UsageResultSchema>;
type CostResult = z.infer<typeof CostResultSchema>;

/**
 * The page envelope around one endpoint's rows, built per endpoint so a costs
 * row can never be counted as usage or the reverse.
 *
 * Pagination used to be read as `object.has_more === true`, which collapsed
 * "the flag says false", "the flag is missing" and "the flag is the string
 * 'true'" into the single answer that both ends pagination and marks the
 * dimension complete. A truncated or off-contract response therefore became an
 * authoritative-looking total: a healthy usage figure missing every page after
 * the first. `has_more` must now be an actual boolean, so a page that cannot
 * state its own completeness invalidates the dimension instead of quietly
 * finishing it. `next_page` stays optional because OpenAI omits it on the last
 * page; when `has_more` is true the caller still demands a usable cursor.
 */
function pageSchema<T extends z.ZodTypeAny>(result: T) {
  return z.strictObject({
    object: z.literal("page"),
    has_more: z.boolean(),
    next_page: z.string().min(1).nullable().optional(),
    data: z.array(z.strictObject({
      object: z.literal("bucket"),
      start_time: z.number().int(),
      end_time: z.number().int(),
      results: z.array(result),
    })),
  });
}

const UsagePageSchema = pageSchema(UsageResultSchema);
const CostPageSchema = pageSchema(CostResultSchema);

/**
 * What a dimension actually got: rows that have already been parsed against
 * their endpoint's schema, and how many pages they came from.
 *
 * This used to hand back the raw page objects for a second, untyped pass to
 * pick apart later. Nothing downstream can now reach an unvalidated field,
 * because no unvalidated field is carried out of this function.
 */
interface PageResult<T> {
  rows: T[];
  pagesRead: number;
  status: DimensionStatus;
}

async function readPages<T>(
  g: GlobalArgs,
  path: string,
  params: URLSearchParams,
  pageSchemaForPath: z.ZodType<{
    has_more: boolean;
    next_page?: string | null;
    data: { results: T[] }[];
  }>,
  callerSignal: AbortSignal,
  doFetch: typeof fetch,
): Promise<PageResult<T>> {
  const rows: T[] = [];
  let pagesRead = 0;
  let page: string | null = null;
  const cursors = new Set<string>();
  const startedAt = Date.now();
  const maxPages = 500;
  const maxElapsedMs = 300_000;
  while (true) {
    callerSignal.throwIfAborted();
    const remaining = maxElapsedMs - (Date.now() - startedAt);
    if (pagesRead >= maxPages || remaining <= 0) {
      return {
        rows,
        pagesRead,
        status: {
          state: pagesRead ? "partial" : "unavailable",
          pagesRead,
          errorKind: remaining <= 0 ? "timeout" : "invalid-response",
          message: remaining <= 0
            ? safeMessage("timeout")
            : "OpenAI pagination exceeded the 500-page observation limit",
        },
      };
    }
    const query = new URLSearchParams(params);
    if (page) query.set("page", page);
    const timeout = AbortSignal.timeout(Math.min(g.timeoutMs, remaining));
    const signal = AbortSignal.any([callerSignal, timeout]);
    try {
      const response = await doFetch(`https://api.openai.com${path}?${query}`, {
        headers: { Authorization: `Bearer ${g.apiKey}` },
        // fetch defaults to redirect: "follow", which would re-send the
        // request to a destination outside the configured HTTPS origin. The README promises requests stay on the official
        // HTTPS origin; only this setting makes that true. "manual" rather
        // than "error" because "error" collapses a redirect into the same
        // untyped TypeError a DNS failure throws, and an attempt to walk the
        // credential off-origin must not be recorded as "unreachable".
        redirect: "manual",
        signal,
      });
      // A 3xx is a refusal, not a response. Runtimes disagree on what a manual
      // redirect looks like — some return the real 3xx status, some an opaque
      // filtered response whose status reads 0 — so both shapes are checked.
      // The Location header is attacker-influenced text and never reaches the
      // status message; only our own literals do.
      if (
        response.type === "opaqueredirect" ||
        (response.status >= 300 && response.status < 400)
      ) {
        return {
          rows,
          pagesRead,
          status: {
            state: pagesRead ? "partial" : "unavailable",
            pagesRead,
            errorKind: "http-error",
            message:
              "OpenAI returned a redirect; the redirect was not followed",
          },
        };
      }
      if (!response.ok) {
        const kind = classifyStatus(response.status);
        return {
          rows,
          pagesRead,
          status: {
            state: pagesRead ? "partial" : "unavailable",
            pagesRead,
            errorKind: kind,
            message: safeMessage(kind),
          },
        };
      }
      const body: unknown = await response.json();
      // The one place a response turns into values. A page that does not parse
      // in full contributes nothing: its rows are never appended, so a
      // half-understood page cannot leave a partial total behind that looks
      // like a whole one.
      const envelope = pageSchemaForPath.safeParse(body);
      if (!envelope.success) {
        return {
          rows,
          pagesRead,
          status: {
            state: pagesRead ? "partial" : "unavailable",
            pagesRead,
            errorKind: "invalid-response",
            message: safeMessage("invalid-response"),
          },
        };
      }
      pagesRead++;
      for (const bucket of envelope.data.data) rows.push(...bucket.results);
      const next = envelope.data.next_page ?? null;
      if (!envelope.data.has_more) {
        return {
          rows,
          pagesRead,
          status: {
            state: "complete",
            pagesRead,
            errorKind: "",
            message: "",
          },
        };
      }
      if (!next || cursors.has(next)) {
        return {
          rows,
          pagesRead,
          status: {
            state: "partial",
            pagesRead,
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
        rows,
        pagesRead,
        status: {
          state: pagesRead ? "partial" : "unavailable",
          pagesRead,
          errorKind: kind,
          message: safeMessage(kind),
        },
      };
    }
  }
}

/**
 * Rows arrive already validated against UsageResultSchema, so this only
 * renames fields into the snapshot's own vocabulary. Nothing here inspects an
 * unvalidated value, because none reaches it.
 *
 * `input_cached_tokens` reads as zero when absent: OpenAI's contract marks it
 * optional and simply omits it when no caching applied, and requiring it once
 * blacked out the whole usage dimension for a response the published contract
 * explicitly permits. The schema is what refuses a cached counter that is
 * present but null or wrongly typed, so the `?? 0` here can only ever stand in
 * for a key OpenAI legitimately left out — never for a value it got wrong.
 *
 * The identifiers keep their null. OpenAI sends project_id or model as null on
 * a row it did not group that way; that null is real data, which is why
 * SnapshotSchema declares those fields nullable and the counters not. A
 * wrongly typed identifier can no longer reach this point and be flattened
 * into the same null, which used to make a garbage row indistinguishable from
 * a legitimately ungrouped one.
 */
function usageFrom(rows: UsageResult[]): UsageBreakdown[] {
  return rows.map((row) => ({
    projectId: row.project_id ?? null,
    model: row.model ?? null,
    inputTokens: row.input_tokens,
    outputTokens: row.output_tokens,
    cachedInputTokens: row.input_cached_tokens ?? 0,
    // OpenAI counts audio separately from text: `input_tokens` and
    // `output_tokens` are the text counters, and audio tokens are reported
    // only in these two fields. They used to be accepted by the row schema and
    // then dropped here, so an audio-bearing response produced a snapshot that
    // called itself complete while its token totals silently omitted every
    // audio token the organization was billed for. They are carried through and
    // aggregated like any other counter; absent reads as zero for the same
    // reason `input_cached_tokens` does — the contract omits the key when the
    // modality did not apply, and the schema is what refuses a present-but-
    // wrong value.
    inputAudioTokens: row.input_audio_tokens ?? 0,
    outputAudioTokens: row.output_audio_tokens ?? 0,
    requests: row.num_model_requests,
  }));
}

interface CostRows {
  rows: CostBreakdown[];
  /** Legal rows carrying no attributable amount; see costsFrom. */
  dropped: number;
}

/**
 * OpenAI's CostsResult contract requires only `object`. The `amount` wrapper,
 * and `value` and `currency` inside it, are all optional. This used to blank
 * the whole cost dimension the moment a single row on a single page omitted
 * any one of them.
 *
 * A row with no amount carries no spend attributable to a currency, so it is
 * dropped and counted, and collect() downgrades the dimension to partial — the
 * drop stays visible instead of quietly lowering the total. That tolerance is
 * for absence only: a present-but-wrong amount, an explicit null, a negative
 * or non-finite value, or a currency that is not a lowercase ISO-4217 code is
 * refused by CostResultSchema at the response boundary and never arrives here
 * to be mistaken for an honest omission.
 */
function costsFrom(rows: CostResult[]): CostRows {
  const output: CostBreakdown[] = [];
  let dropped = 0;
  for (const row of rows) {
    const value = row.amount?.value;
    const currency = row.amount?.currency;
    if (value === undefined || currency === undefined) {
      dropped++;
      continue;
    }
    output.push({
      projectId: row.project_id ?? null,
      lineItem: row.line_item ?? null,
      value,
      currency,
    });
  }
  return { rows: output, dropped };
}

async function collect(
  args: z.infer<typeof CollectArgsSchema>,
  ctx: ModelContext,
) {
  const g = GlobalArgsSchema.parse(ctx.globalArgs);
  // Bound once here so both dimensions share one transport, and so production
  // -- which never sets ctx.fetch -- always lands on the platform fetch.
  const doFetch = ctx.fetch ?? globalThis.fetch;
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
  // Each dimension is read against its own page schema, so a costs row can
  // never be summed as usage or the reverse even if OpenAI answered one path
  // with the other's body.
  const [usageResult, costResult] = await Promise.all([
    readPages(
      g,
      "/v1/organization/usage/completions",
      usageParams,
      UsagePageSchema,
      ctx.signal,
      doFetch,
    ),
    readPages(
      g,
      "/v1/organization/costs",
      costParams,
      CostPageSchema,
      ctx.signal,
      doFetch,
    ),
  ]);
  let usageRows: UsageBreakdown[] | null = usageFrom(usageResult.rows);
  const costData = costsFrom(costResult.rows);
  let costRows: CostBreakdown[] | null = costData.rows;

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
    inputAudioTokens: number;
    outputAudioTokens: number;
    requests: number;
  } | null = null;
  if (usageRows !== null) {
    usageTotals = {
      inputTokens: usageRows.reduce((n, r) => n + r.inputTokens, 0),
      outputTokens: usageRows.reduce((n, r) => n + r.outputTokens, 0),
      cachedInputTokens: usageRows.reduce((n, r) => n + r.cachedInputTokens, 0),
      inputAudioTokens: usageRows.reduce((n, r) => n + r.inputAudioTokens, 0),
      outputAudioTokens: usageRows.reduce((n, r) => n + r.outputAudioTokens, 0),
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
      state: usageResult.pagesRead ? "partial" : "unavailable",
      pagesRead: usageResult.pagesRead,
      errorKind: "invalid-response",
      message: safeMessage("invalid-response"),
    };
  }
  if (costRows === null) {
    costResult.status = {
      state: costResult.pagesRead ? "partial" : "unavailable",
      pagesRead: costResult.pagesRead,
      errorKind: "invalid-response",
      message: safeMessage("invalid-response"),
    };
  } else if (
    costData.dropped > 0 && costResult.status.state === "complete"
  ) {
    // Dropped rows are contract-legal but unattributable, not a protocol error,
    // so the dimension stays usable and only loses its claim to completeness.
    // errorKind stays empty because nothing about the response was invalid;
    // the dashboard renders a partial section from the message alone.
    costResult.status = {
      state: "partial",
      pagesRead: costResult.pagesRead,
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
      pagesRead: usageResult.pagesRead,
      errorKind: "invalid-response",
      message: safeMessage("invalid-response"),
    },
    costStatus: {
      state: "unavailable",
      pagesRead: costResult.pagesRead,
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
  version: "2026.09.05.1",
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
