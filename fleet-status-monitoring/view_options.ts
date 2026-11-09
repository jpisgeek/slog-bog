import { z } from "npm:zod@4";
const LinkPath = z.string().min(1).max(200).regex(
  /^\/(?:[A-Za-z0-9][A-Za-z0-9/_-]*)?$/,
).refine(
  (p) => p === "/" || (!p.endsWith("/") && !p.includes("//")),
  "Use a same-origin path without a trailing slash",
);
const ReportPath = LinkPath.refine(
  (p) => p !== "/",
  "Use a report path below the origin root",
);
/** Same-origin navigation only; optional links are omitted unless configured. */
export const ViewOptions = z.strictObject({
  reportPath: ReportPath.default("/fleet").describe(
    "Canonical route supplied by the existing host",
  ),
  dashboardPath: LinkPath.nullable().default("/dashboard").describe(
    "Optional native dashboard link",
  ),
  questPath: LinkPath.nullable().default(null).describe(
    "Optional Quest example link; disabled by default",
  ),
});
/** Validated rendering options; the refresh route is derived from reportPath. */
export type FleetViewOptions = z.infer<typeof ViewOptions>;
