/**
 * mise toolchain drift across a fleet.
 *
 * mise already installs tools and pins versions, and it does that well. This
 * model installs nothing, upgrades nothing, and trusts nothing. It walks the
 * fleet, asks each host what it is actually running, and writes down where
 * that disagrees with what the host's own config asked for.
 *
 * The distinction the whole model is built around: a host that did not answer
 * is not a host with nothing to report. mise is routinely absent from a
 * non-login shell's PATH, and an empty tool list from a host that never ran
 * mise reads exactly like a host that is perfectly clean. So every failure to
 * measure is recorded as a failure to measure, never as a zero.
 */
import { z } from "npm:zod@4";

/**
 * Absolute path, and only characters that cannot change the meaning of the
 * single-quoted remote command they are interpolated into. No quote, no
 * semicolon, no dollar, no backtick, no whitespace.
 */
const SAFE_ABS_PATH = /^\/[A-Za-z0-9._/-]*$/;
/** Same character class, but a bare command name like `mise` is also fine. */
const SAFE_BIN_PATH = /^[A-Za-z0-9._/-]+$/;

const SshSchema = z.object({
  // host/user become the positional `user@host` argument to ssh. A value
  // starting with "-" would be read as an ssh option (-oProxyCommand=...).
  host: z.string().min(1).refine((v) => !v.startsWith("-"), {
    message: "ssh.host must not start with '-'",
  }),
  user: z.string().min(1).refine((v) => !v.startsWith("-"), {
    message: "ssh.user must not start with '-'",
  }),
  port: z.number().int().positive().default(22),
});

export const NodeSchema = z.object({
  name: z.string().min(1).describe("Label for this host in the written data"),
  ssh: SshSchema.optional().describe(
    "Reach this host over SSH. Omit for the machine swamp is running on.",
  ),
  dir: z
    .string()
    .refine(
      (v) => SAFE_ABS_PATH.test(v) && !v.split("/").includes(".."),
      {
        message:
          "dir must be an absolute path made of [A-Za-z0-9._/-] with no '..' " +
          "segment. It is interpolated into the remote command, so a value " +
          "that could change that command's meaning is refused rather than " +
          "stripped: a half-repaired path that silently measures the wrong " +
          "directory is worse than a config error.",
      },
    )
    .optional()
    .describe(
      "Which directory's config to evaluate. mise config is directory-scoped, " +
        "so without this the question has no fixed answer. Defaults to the " +
        "swamp working directory locally and the login directory over SSH.",
    ),
  misePath: z
    .string()
    .refine((v) => SAFE_BIN_PATH.test(v) && !v.startsWith("-"), {
      message:
        "misePath must match [A-Za-z0-9._/-] and must not start with '-'",
    })
    .default("mise")
    .describe(
      "Path to the mise binary. Worth setting for SSH hosts: a non-login " +
        "shell often has no ~/.local/bin on PATH, and mise lives there.",
    ),
});

export const GlobalArgsSchema = z.object({
  nodes: z
    .array(NodeSchema)
    .min(1)
    .refine(
      (ns) => new Set(ns.map((n) => n.name)).size === ns.length,
      { message: "Duplicate node name: each node needs its own label" },
    ),
  timeoutSec: z.number().int().positive().default(15),
  maxConcurrency: z
    .number()
    .int()
    .positive()
    .default(8)
    .describe(
      "How many hosts to poll at once. A long nodes list otherwise spawns an " +
        "unbounded pile of ssh processes at the same time.",
    ),
  expect: z
    .record(z.string(), z.string())
    .default({})
    .describe(
      "Optional fleet-wide expectation, e.g. {node: '22'}. A version matches " +
        "when its dot-separated segments start with these, so '22' accepts " +
        "22.23.2 but '22.2' does not. Omit it and each host is judged only " +
        "against its own config.",
    ),
});

export const model = {
  type: "@jpisgeek/mise",
  version: "2026.08.24.1",
  globalArguments: GlobalArgsSchema,
  resources: {},
  methods: {},
};
