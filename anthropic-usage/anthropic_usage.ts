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
/**
 * How the vendor's own `data_refreshed_at` evidence came back.
 *
 * These three outcomes used to collapse into a single null. `if (refreshed)
 * refreshedAt = refreshed` dropped a present-but-unusable value on the floor,
 * leaving the snapshot indistinguishable from one where Anthropic sent no
 * refresh evidence at all — and the dashboard then substituted collection time
 * and labelled the section fresh. A response whose freshness evidence was
 * garbage therefore rendered as a healthy, recently-refreshed dashboard.
 *
 * "absent"   Anthropic sent no data_refreshed_at (or an explicit null).
 * "observed" Anthropic sent a usable RFC 3339 timestamp; dataRefreshedAt holds
 *            it in canonical Z form.
 * "invalid"  Anthropic sent a value that is not a usable timestamp, or two
 *            pages of one walk disagreed about it. This is sticky across that
 *            walk: a response that contradicts its own freshness claim is not
 *            freshness evidence, so the dimension's timestamp goes null and the
 *            dashboard reports unknown freshness for that section rather than a
 *            fresh observation. It is NOT carried to the other dimension, which
 *            has its own evidence and states its own case.
 */
const RefreshStateSchema = z.enum(["absent", "observed", "invalid"]);
type RefreshState = z.infer<typeof RefreshStateSchema>;
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
  // Both Anthropic cost endpoints report decimal fractional cents (USD minor
  // units). Preserve that decimal exactly; never relabel it as dollars.
  // https://platform.claude.com/docs/en/manage-claude/usage-cost-api
  amountMinor: z.string().regex(/^\d+(\.\d+)?$/),
  currency: z.string().regex(/^[A-Z]{3}$/),
});
const SnapshotSchema = z.object({
  provider: z.literal("anthropic"),
  accountKind: z.enum(["platform", "enterprise"]),
  collectedAt: z.iso.datetime(),
  coverageStart: z.iso.datetime(),
  coverageEnd: z.iso.datetime(),
  // Freshness belongs to the endpoint it came from and is never merged. One
  // pair of fields for both dimensions meant a usage timestamp answered for
  // cost data that carried none of its own; see the note in collect().
  usageRefreshedAt: z.iso.datetime().nullable(),
  usageRefreshState: RefreshStateSchema,
  costRefreshedAt: z.iso.datetime().nullable(),
  costRefreshState: RefreshStateSchema,
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
  /** Per-call transport; never modifies another caller's requests. */
  fetch?: typeof fetch;
  writeResource(
    spec: string,
    name: string,
    data: z.infer<typeof SnapshotSchema>,
    options?: { tags?: Record<string, string> },
  ): Promise<unknown>;
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
/**
 * Endpoint-specific response schemas, applied where the bytes arrive.
 *
 * Responses used to be walked field by field with `typeof` checks after the
 * fact, over `Record<string, unknown>` bags that no schema ever described. Two
 * concrete failures came out of that, and both published a number that was not
 * true:
 *
 *   - `if (object.has_more !== true)` read a missing, null or string
 *     `"true"` pagination flag as "there is no next page", which is the one
 *     answer that both ends the walk and marks the dimension complete. A
 *     truncated or off-contract response became an authoritative total.
 *   - `typeof item.model === "string" ? item.model : null` turned a grouping
 *     dimension this collector explicitly asked Anthropic to group by — one
 *     that was missing, or a number, or an object — into the same null the API
 *     legitimately sends for an ungrouped row. A malformed breakdown was
 *     indistinguishable from an honest one and was summed into a "complete"
 *     total.
 *
 * Both are now schema questions, answered before any value is read:
 *
 *   - `strictObject` at every level (page, bucket, result row). A key this
 *     version does not model is a key it has not validated, so the page does
 *     not parse and the dimension degrades to invalid-response instead of
 *     being totalled from the part that was recognised.
 *   - One schema per endpoint AND per account kind, because the two products
 *     return different shapes and this collector sends them different
 *     `group_by[]` values. The required fields differ enough that a cost row
 *     cannot parse as a usage row, or a Platform row as an Enterprise one:
 *     Anthropic's reports carry no `object` discriminator, so the required
 *     field set is the discriminator. One endpoint answering with another's
 *     body degrades that dimension rather than being counted.
 *   - Every grouping in the request is required in the response. Requesting
 *     `group_by[]=workspace_id&group_by[]=model` and accepting a row with no
 *     `model` key is accepting a different report than the one that was asked
 *     for.
 *   - `.optional()` and `.nullable()` are not interchangeable. An absent key is
 *     the contract's own "no value". An explicit null is a value Anthropic
 *     chose to send, accepted only on the identifier dimensions it genuinely
 *     nulls out for an unattributed row — the same fields UsageRowSchema and
 *     CostRowSchema declare nullable — and refused on every counter and on
 *     every currency amount.
 *
 * The forward-compatibility cost is real and is documented in the README: if
 * Anthropic adds a field to these result objects, that dimension reads
 * invalid-response until this package models it. Dimensions Anthropic already
 * returns without being asked are modelled optional below so a live response is
 * not blacked out for carrying them. The failure direction is deliberate — a
 * dimension that is visibly unavailable, never a total quietly computed from
 * the fields we happened to recognise.
 */
/** A grouping this collector requested: the key must be present. */
const grouping = () => z.string().nullable();
/** A dimension Anthropic may attach unasked: absent, null or a string. */
const dimension = () => z.string().nullable().optional();
const CacheCreationSchema = z.strictObject({
  // Absent means "no cache activity in this grouping", which usageRows() reads
  // as 0. That tolerance is for absence only; a present but wrong-typed or
  // explicitly null counter is refused here. See the optionalInteger note that
  // this schema replaced, and the README caveat covering the zero.
  ephemeral_5m_input_tokens: z.number().int().nonnegative().optional(),
  ephemeral_1h_input_tokens: z.number().int().nonnegative().optional(),
});
const ServerToolUseSchema = z.strictObject({
  web_search_requests: z.number().int().nonnegative().optional(),
});
const usageCounters = {
  uncached_input_tokens: z.number().int().nonnegative(),
  cache_read_input_tokens: z.number().int().nonnegative(),
  output_tokens: z.number().int().nonnegative(),
  cache_creation: CacheCreationSchema.optional(),
  server_tool_use: ServerToolUseSchema.optional(),
};
/**
 * Platform Messages Usage Report row, grouped by workspace_id and model.
 *
 * `requests` is deliberately not modelled. This package reports the Platform
 * request count as unsupported and stores null for it; if the Platform report
 * began returning one, that claim would be false, so the row stops parsing and
 * says so rather than continuing to publish "unsupported" over a number that
 * arrived.
 */
const PlatformUsageResultSchema = z.strictObject({
  ...usageCounters,
  workspace_id: grouping(),
  model: grouping(),
  api_key_id: dimension(),
  service_tier: dimension(),
  context_window: dimension(),
  inference_geo: dimension(),
  speed: dimension(),
});
/** Enterprise Analytics usage row, grouped by product and model. */
const EnterpriseUsageResultSchema = z.strictObject({
  ...usageCounters,
  requests: z.number().int().nonnegative(),
  product: grouping(),
  model: grouping(),
  workspace_id: dimension(),
  service_tier: dimension(),
  context_window: dimension(),
  inference_geo: dimension(),
  speed: dimension(),
  claude_tag_category: dimension(),
  claude_tag_user_id: dimension(),
  rbac_group_id: dimension(),
  slack_channel_id: dimension(),
});
// Pinned to the exact spellings SnapshotSchema stores, so a row can never
// introduce an amount or currency the snapshot would reject at the end of a
// wholly successful collection.
const costAmount = {
  amount: z.string().regex(/^\d+(\.\d+)?$/),
  currency: z.string().regex(/^[A-Z]{3}$/),
};
/** Platform Cost Report row, grouped by workspace_id and description. */
const PlatformCostResultSchema = z.strictObject({
  ...costAmount,
  workspace_id: grouping(),
  description: grouping(),
  model: dimension(),
  product: dimension(),
  cost_type: dimension(),
  context_window: dimension(),
  inference_geo: dimension(),
  speed: dimension(),
  token_type: dimension(),
  service_tier: dimension(),
});
/** Enterprise Analytics cost row, grouped by product, model and cost_type. */
const EnterpriseCostResultSchema = z.strictObject({
  ...costAmount,
  product: grouping(),
  model: grouping(),
  cost_type: grouping(),
  description: dimension(),
  workspace_id: dimension(),
  context_window: dimension(),
  inference_geo: dimension(),
  speed: dimension(),
  token_type: dimension(),
  service_tier: dimension(),
  list_amount: z.string().regex(/^\d+(\.\d+)?$/).optional(),
  requests: z.number().int().nonnegative().optional(),
  claude_tag_category: dimension(),
  claude_tag_user_id: dimension(),
  rbac_group_id: dimension(),
  slack_channel_id: dimension(),
});
type PlatformUsageResult = z.infer<typeof PlatformUsageResultSchema>;
type EnterpriseUsageResult = z.infer<typeof EnterpriseUsageResultSchema>;
type PlatformCostResult = z.infer<typeof PlatformCostResultSchema>;
type EnterpriseCostResult = z.infer<typeof EnterpriseCostResultSchema>;
/**
 * RFC 3339 shape, both spellings of the zone, with the calendar components
 * captured so instant() can prove they describe a real date. See the
 * CollectArgsSchema note: the snapshot stores z.iso.datetime(), which is
 * Z-only. Declared up here rather than beside instant() because the page
 * schemas below are built at module load and reference it.
 */
const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;
/**
 * The paged envelope around one endpoint's rows.
 *
 * `has_more` must be an actual boolean: a page that cannot state its own
 * completeness invalidates the dimension instead of quietly finishing the walk.
 * `next_page` stays optional because Anthropic omits or nulls it on the last
 * page; when `has_more` is true readPages() still demands a usable cursor.
 *
 * A bucket's `starting_at`/`ending_at` are the response's claim about WHICH
 * period its rows describe, so they are timestamps here rather than any
 * nonempty string. Shape alone is not enough — readPages() also checks each
 * bucket against the window that was actually requested — but a boundary that
 * is not a timestamp cannot be checked at all, and used to be stored as exact
 * coverage of the requested window without ever being read.
 *
 * `data_refreshed_at` is typed loosely on purpose — a present string that is
 * not a timestamp must be classifiable as invalid freshness evidence rather
 * than blacking out a page of otherwise good usage. A present non-string is
 * still refused here, which is the other outcome the same requirement allows.
 */
function pageSchema<T extends z.ZodType>(result: T) {
  return z.strictObject({
    data: z.array(z.strictObject({
      starting_at: z.string().regex(RFC3339),
      ending_at: z.string().regex(RFC3339),
      results: z.array(result),
    })),
    has_more: z.boolean(),
    next_page: z.string().min(1).nullable().optional(),
    data_refreshed_at: z.string().nullable().optional(),
    organization_id: z.string().optional(),
  });
}
const PlatformUsagePageSchema = pageSchema(PlatformUsageResultSchema);
const EnterpriseUsagePageSchema = pageSchema(EnterpriseUsageResultSchema);
const PlatformCostPageSchema = pageSchema(PlatformCostResultSchema);
const EnterpriseCostPageSchema = pageSchema(EnterpriseCostResultSchema);
/** The structural minimum readPages() needs from any endpoint's page schema. */
interface RawPage<T> {
  data: { starting_at: string; ending_at: string; results: T[] }[];
  has_more: boolean;
  next_page?: string | null;
  data_refreshed_at?: string | null;
}
/**
 * What one dimension's walk produced: rows already parsed against their own
 * endpoint's schema, plus the evidence about the walk itself.
 *
 * Nothing downstream can reach an unvalidated field, because no unvalidated
 * field is carried out of readPages().
 */
interface Walk<T> {
  rows: T[];
  pagesRead: number;
  status: Status;
  refreshedAt: string | null;
  refreshState: RefreshState;
  groupedAtCap: boolean;
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
/**
 * collect() asks for bucket_width=1d, so a bucket wider than one UTC day is not
 * the report it requested. Without a width ceiling one bucket claiming to span
 * years would still overlap the requested window and drag every row inside it
 * into a total presented as that window's.
 */
const BUCKET_WIDTH_MS = 86_400_000;
/**
 * One RFC 3339 instant in epoch milliseconds, or null.
 *
 * Textual shape used to be the whole test, and `Date.parse` normalizes rather
 * than refuses: "2026-02-30T00:00:00Z" is not a date, but Date.parse turns it
 * into March 2 and returns a finite number, so a calendar-impossible value was
 * canonicalized and published as Anthropic's own freshness evidence — and, on a
 * bucket boundary, as the period a row belongs to. Round-tripping the captured
 * components through Date.UTC is what refuses it: a value that had to be
 * normalized comes back as different components. That single check also covers
 * month 00, month 13 and hour 24, and it refuses a leap second (":60") because a
 * value we cannot round-trip is exactly what this function exists to reject.
 * Only once the components are proven exact is Date.parse trusted for the
 * instant itself, which keeps the fractional seconds and the zone offset the
 * pattern allows. Four-digit years below 0100 are refused as a side effect of
 * Date.UTC's two-digit-year mapping; Anthropic does not report them.
 */
function instant(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const parts = RFC3339.exec(value);
  if (!parts) return null;
  const [year, month, day, hour, minute, second] = parts.slice(1).map(Number);
  const back = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    back.getUTCFullYear() !== year || back.getUTCMonth() !== month - 1 ||
    back.getUTCDate() !== day || back.getUTCHours() !== hour ||
    back.getUTCMinutes() !== minute || back.getUTCSeconds() !== second
  ) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}
/**
 * data_refreshed_at used to be copied into the snapshot on nothing more than
 * `typeof === "string"`. Anthropic documents it as RFC 3339, which permits
 * "2026-08-29T10:00:00+00:00" — a value SnapshotSchema rejects — so a legal
 * offset-form timestamp threw a ZodError at the very end of a wholly successful
 * two-endpoint collection and nothing was written at all. Canonicalize to UTC
 * (same instant, Z spelling); anything instant() cannot prove is a real point in
 * time returns null here and is recorded as RefreshState "invalid" by the
 * caller.
 */
function timestamp(value: unknown): string | null {
  const ms = instant(value);
  return ms === null ? null : new Date(ms).toISOString();
}
async function readPages<T>(
  g: Globals,
  path: string,
  params: URLSearchParams,
  // The window this walk asked for, in epoch milliseconds, so every bucket can
  // be checked against it. collect() computes it from its own validated
  // arguments — the same values it puts in `params` — rather than re-parsing
  // them out of the query string.
  window: { start: number; end: number },
  schema: z.ZodType<RawPage<T>>,
  caller: AbortSignal,
  fetcher: typeof fetch,
): Promise<Walk<T>> {
  const rows: T[] = [];
  const cursors = new Set<string>();
  let pagesRead = 0;
  let page: string | null = null;
  let refreshedAt: string | null = null;
  let refreshState: RefreshState = "absent";
  let groupedAtCap = false;
  // End of the last bucket accepted anywhere in this walk. Pagination continues
  // one time series, so a bucket that starts before this point either repeats a
  // period already counted or overlaps one, and either way would add the same
  // day's rows to the total twice.
  let bucketFloor = Number.NEGATIVE_INFINITY;
  const startedAt = Date.now();
  const done = (status: Status): Walk<T> => ({
    rows,
    pagesRead,
    status,
    refreshedAt,
    refreshState,
    groupedAtCap,
  });
  const degraded = (kind: Status["errorKind"], text?: string): Walk<T> =>
    done({
      state: pagesRead
        ? "partial"
        : kind === "unsupported"
        ? "unsupported"
        : "unavailable",
      pagesRead,
      errorKind: kind,
      message: text ?? message(kind),
    });
  while (true) {
    caller.throwIfAborted();
    if (pagesRead >= MAX_PAGES || Date.now() - startedAt >= MAX_ELAPSED_MS) {
      const capped = pagesRead >= MAX_PAGES;
      return done({
        state: pagesRead ? "partial" : "unavailable",
        pagesRead,
        errorKind: capped ? "" : "timeout",
        message: capped
          ? `Stopped after ${MAX_PAGES} pages while Anthropic still reported more results`
          : message("timeout"),
      });
    }
    const query = new URLSearchParams(params);
    if (page) query.set("page", page);
    const timeout = AbortSignal.timeout(
      Math.min(g.timeoutMs, MAX_ELAPSED_MS - (Date.now() - startedAt)),
    );
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
      if (!response.ok) return degraded(statusKind(response.status));
      const body: unknown = await response.json();
      // The one place a response becomes values. A page that does not parse in
      // full contributes nothing: its rows are never appended, so a
      // half-understood page cannot leave behind a partial total that looks
      // like a whole one.
      const envelope = schema.safeParse(body);
      if (!envelope.success) return degraded("invalid-response");
      // Bucket boundaries were parsed but never read, so a response holding
      // last quarter's buckets — or the same day twice — was summed and stored
      // as exact coverage of the window that was requested. Check every bucket
      // in the page before a single row is appended, so a page describing the
      // wrong period contributes nothing rather than leaving half a total
      // behind, and check it before pagesRead++ so the walk degrades the same
      // way an unparseable page does.
      //
      // Overlap with the window, not containment: Anthropic aligns 1d buckets
      // to UTC midnight, so a window that does not begin at midnight
      // legitimately gets an edge bucket straddling the boundary, and demanding
      // containment would black out real usage. With the width ceiling that
      // bounds the slop to one day at each edge; a bucket sharing no instant
      // with the requested window is refused outright.
      let cursor = bucketFloor;
      for (const bucket of envelope.data.data) {
        const from = instant(bucket.starting_at);
        const to = instant(bucket.ending_at);
        if (
          from === null || to === null || from >= to ||
          to - from > BUCKET_WIDTH_MS ||
          to <= window.start || from >= window.end ||
          from < cursor
        ) return degraded("invalid-response");
        cursor = to;
      }
      bucketFloor = cursor;
      pagesRead++;
      for (const bucket of envelope.data.data) {
        if (bucket.results.length >= GROUP_CAP) groupedAtCap = true;
        rows.push(...bucket.results);
      }
      const refreshed = envelope.data.data_refreshed_at;
      if (refreshed !== undefined && refreshed !== null) {
        const parsed = timestamp(refreshed);
        // Each page's evidence is checked against what the walk already holds
        // instead of overwriting it. Pages of one walk that name different
        // refresh times contradict each other about when this data was last
        // refreshed, and a contradiction is not evidence: keep no timestamp and
        // report invalid, exactly as for a value that is not a timestamp at
        // all. The last page's answer used to silently become the whole walk's.
        if (
          parsed === null || (refreshedAt !== null && refreshedAt !== parsed)
        ) {
          refreshState = "invalid";
          refreshedAt = null;
        } else {
          refreshedAt = parsed;
          if (refreshState !== "invalid") refreshState = "observed";
        }
      }
      if (!envelope.data.has_more) {
        return done({
          state: "complete",
          pagesRead,
          errorKind: "",
          message: "",
        });
      }
      const next = envelope.data.next_page ?? null;
      if (!next || cursors.has(next)) {
        return done({
          state: "partial",
          pagesRead,
          errorKind: "invalid-response",
          message: message("invalid-response"),
        });
      }
      cursors.add(next);
      page = next;
    } catch (error) {
      if (caller.aborted) throw error;
      return degraded(
        timeout.aborted
          ? "timeout"
          : error instanceof SyntaxError
          ? "invalid-response"
          : "unreachable",
      );
    }
  }
}
/** Re-type a finished walk once its rows have been mapped to snapshot shape. */
function mapped<T, U>(walk: Walk<T>, map: (rows: T[]) => U[]): Walk<U> {
  return { ...walk, rows: map(walk.rows) };
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
/**
 * Rows arrive already validated, so these only rename fields into the
 * snapshot's vocabulary. Nothing here inspects an unvalidated value.
 *
 * An absent cache sub-field reads as 0: a grouping with no 1-hour-cache
 * activity may legitimately omit the sub-field rather than send 0, and
 * requiring it once discarded usage for a whole window over a response the
 * contract permits. CacheCreationSchema is what refuses a present-but-wrong or
 * explicitly null counter, so this `?? 0` can only ever stand in for a key
 * Anthropic left out — never for a value it got wrong. The remaining
 * undercount risk if Anthropic silently stops sending a counter it used to send
 * is stated in the README.
 *
 * The identifiers keep their null: Anthropic sends null on a dimension it did
 * not attribute, which is why UsageRowSchema declares them nullable and the
 * counters not. A missing or wrongly typed grouping can no longer arrive here
 * to be flattened into that same null.
 */
function platformUsageRows(rows: PlatformUsageResult[]): UsageRow[] {
  return rows.map((row) => ({
    product: null,
    model: row.model,
    workspaceId: row.workspace_id,
    uncachedInputTokens: row.uncached_input_tokens,
    cacheCreation5mTokens: row.cache_creation?.ephemeral_5m_input_tokens ?? 0,
    cacheCreation1hTokens: row.cache_creation?.ephemeral_1h_input_tokens ?? 0,
    cacheReadTokens: row.cache_read_input_tokens,
    outputTokens: row.output_tokens,
    requests: null,
  }));
}
function enterpriseUsageRows(rows: EnterpriseUsageResult[]): UsageRow[] {
  return rows.map((row) => ({
    product: row.product,
    model: row.model,
    workspaceId: row.workspace_id ?? null,
    uncachedInputTokens: row.uncached_input_tokens,
    cacheCreation5mTokens: row.cache_creation?.ephemeral_5m_input_tokens ?? 0,
    cacheCreation1hTokens: row.cache_creation?.ephemeral_1h_input_tokens ?? 0,
    cacheReadTokens: row.cache_read_input_tokens,
    outputTokens: row.output_tokens,
    requests: row.requests,
  }));
}
// One spelling of the amount for both account kinds. The old ternary
// (`enterprise ? amount : addDecimal("0", amount)`) performed no unit
// conversion in either branch — it only chose whether to normalize the string —
// so the same value was stored differently depending on account kind, and
// "125.00" survived in an Enterprise breakdown next to a "125" total.
// Normalize both so breakdowns compare equal to the totals addDecimal produces.
function platformCostRows(rows: PlatformCostResult[]): CostRow[] {
  return rows.map((row) => ({
    product: row.product ?? null,
    model: row.model ?? null,
    workspaceId: row.workspace_id,
    description: row.description,
    amountMinor: addDecimal("0", row.amount),
    currency: row.currency,
  }));
}
function enterpriseCostRows(rows: EnterpriseCostResult[]): CostRow[] {
  return rows.map((row) => ({
    product: row.product,
    model: row.model,
    workspaceId: row.workspace_id ?? null,
    description: row.description ?? null,
    amountMinor: addDecimal("0", row.amount),
    currency: row.currency,
  }));
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
  // Every grouping requested here is a required field in the matching result
  // schema above. The two lists must stay in step: asking for a grouping and
  // accepting a response without it is accepting a different report.
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
  const usagePath = `${prefix}/${
    enterprise ? "usage_report" : "usage_report/messages"
  }`;
  const costPath = `${prefix}/cost_report`;
  // Each dimension is read against the schema for its own endpoint and account
  // kind, so one endpoint answering with another's body degrades that dimension
  // instead of being totalled.
  // The window every returned bucket is checked against. Both values are
  // already validated RFC 3339 by CollectArgsSchema and ordered by the guard at
  // the top of collect().
  const window = {
    start: Date.parse(input.startingAt),
    end: Date.parse(input.endingAt),
  };
  const [usageWalk, costWalk] = await Promise.all([
    enterprise
      ? readPages(
        g,
        usagePath,
        usageParams,
        window,
        EnterpriseUsagePageSchema,
        ctx.signal,
        ctx.fetch ?? fetch,
      ).then((walk) => mapped(walk, enterpriseUsageRows))
      : readPages(
        g,
        usagePath,
        usageParams,
        window,
        PlatformUsagePageSchema,
        ctx.signal,
        ctx.fetch ?? fetch,
      ).then((walk) => mapped(walk, platformUsageRows)),
    enterprise
      ? readPages(
        g,
        costPath,
        costParams,
        window,
        EnterpriseCostPageSchema,
        ctx.signal,
        ctx.fetch ?? fetch,
      ).then((walk) => mapped(walk, enterpriseCostRows))
      : readPages(
        g,
        costPath,
        costParams,
        window,
        PlatformCostPageSchema,
        ctx.signal,
        ctx.fetch ?? fetch,
      ).then((walk) => mapped(walk, platformCostRows)),
  ]);
  const totals = new Map<string, string>();
  for (const row of costWalk.rows) {
    totals.set(
      row.currency,
      addDecimal(totals.get(row.currency) ?? "0", row.amountMinor),
    );
  }
  const sum = (key: keyof UsageRow) =>
    usageWalk.rows.reduce((n, row) => n + (row[key] as number), 0);
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
    // Each dimension carries its own freshness, unchanged by what the other
    // one saw. `dataRefreshedAt: usageWalk.refreshedAt ?? costWalk.refreshedAt`
    // under a single merged state let one fresh usage timestamp stand as the
    // refresh time of cost data that had reported none of its own — or a
    // different one — and the dashboard rendered both sections equally fresh
    // from it. A dimension keeps a timestamp only when its own walk observed
    // one; "absent" and "invalid" both store null, and stay distinguishable
    // through the state field.
    usageRefreshedAt: usageWalk.refreshState === "observed"
      ? usageWalk.refreshedAt
      : null,
    usageRefreshState: usageWalk.refreshState,
    costRefreshedAt: costWalk.refreshState === "observed"
      ? costWalk.refreshedAt
      : null,
    costRefreshState: costWalk.refreshState,
    usageStatus: usageWalk.status,
    costStatus: costWalk.status,
    usage: usageWalk.status.state === "unavailable" ||
        usageWalk.status.state === "unsupported"
      ? null
      : {
        uncachedInputTokens: sum("uncachedInputTokens"),
        cacheCreation5mTokens: sum("cacheCreation5mTokens"),
        cacheCreation1hTokens: sum("cacheCreation1hTokens"),
        cacheReadTokens: sum("cacheReadTokens"),
        outputTokens: sum("outputTokens"),
        requests: enterprise ? sum("requests") : null,
        breakdowns: usageWalk.rows,
        groupedTop100Cap: enterprise && usageWalk.groupedAtCap,
      },
    costs: costWalk.status.state === "unavailable" ||
        costWalk.status.state === "unsupported"
      ? null
      : {
        totals: [...totals].map(([currency, amountMinor]) => ({
          currency,
          amountMinor,
        })),
        breakdowns: costWalk.rows,
        groupedTop100Cap: enterprise && costWalk.groupedAtCap,
      },
  };
  // Everything above this line is fail-soft: an unusable response degrades to a
  // status and usage/costs go null, never to a reassuring zero. This parse is
  // the single fail-hard step, and it is now a last-resort net rather than the
  // first line of defence — row-level guards do not survive addition, so a page
  // of individually legal counters can still sum past Number.MAX_SAFE_INTEGER.
  // A late schema violation used to throw an uncaught ZodError after both
  // paginated fetches had already succeeded, and nothing at all was written.
  // Degrade to the same invalid-response shape the rest of collect() uses so the
  // operator gets a snapshot that says so.
  let snapshot: z.infer<typeof SnapshotSchema>;
  const parsed = SnapshotSchema.safeParse(candidate);
  if (parsed.success) {
    snapshot = parsed.data;
  } else {
    const degrade = (walk: Walk<unknown>): Status => ({
      state: walk.pagesRead ? "partial" : "unavailable",
      pagesRead: walk.pagesRead,
      errorKind: "invalid-response",
      message: message("invalid-response"),
    });
    snapshot = SnapshotSchema.parse({
      provider: "anthropic",
      accountKind: g.accountKind,
      collectedAt: new Date().toISOString(),
      coverageStart,
      coverageEnd,
      // No timestamp survives this path, so a walk that observed one is
      // recorded as "absent" rather than claiming an observation the snapshot
      // no longer carries. "invalid" is kept: it is a statement about the
      // response, and it stays true here.
      usageRefreshedAt: null,
      usageRefreshState: usageWalk.refreshState === "invalid"
        ? "invalid"
        : "absent",
      costRefreshedAt: null,
      costRefreshState: costWalk.refreshState === "invalid"
        ? "invalid"
        : "absent",
      usageStatus: degrade(usageWalk),
      costStatus: degrade(costWalk),
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
  version: "2026.09.05.1",
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
