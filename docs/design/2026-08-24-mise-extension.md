# @jpisgeek/mise design

Status: approved, not yet implemented
Date: 2026-08-24
Target version: `2026.08.24.1`

## What it is

A read-only fleet sweep of mise toolchain state. One method, `discover`, polls
every configured node and records which toolchain each host is actually
running, and where that disagrees with what the host's own config asks for.

The non-goal, stated the way `netdata` states its own: mise already installs
and pins tools, and does it well. This installs nothing, upgrades nothing, and
trusts nothing. It records state truth so a workflow can act on the gap.

It never invokes `mise token`, `mise settings`, `mise install`, `mise upgrade`,
or `mise trust` without `--show`. Nothing it runs mutates state or surfaces
credentials. The full set of commands is fixed and listed below.

## Verified command surface

Probed against mise `2026.8.12 macos-arm64` on 2026-08-24. These are real
outputs with paths replaced by placeholders, not assumed shapes.

`mise ls --current --json` is the primary source. Keyed by tool name:

```json
{
  "node": [
    {
      "version": "22.23.2",
      "requested_version": "22",
      "install_path": "<home>/.local/share/mise/installs/node/22.23.2",
      "source": { "type": "mise.toml", "path": "<dir>/mise.toml" },
      "installed": true,
      "active": true
    }
  ]
}
```

A tool the config requests but the host lacks comes back in the same shape with
`"installed": false, "active": false`, and `version` still resolved. Config
`node = "18"` yields `"version": "18.20.8"`. Configured-but-missing is
therefore directly observable, not inferred.

`mise config ls --json` returns `[{ "path": "<dir>/mise.toml", "tools": ["node", "python"] }]`.
It carries no trust field.

`mise outdated --json` returns `{}` when nothing is behind. It covers only
tools in the current config unless `--inactive` is passed.

`mise trust --show` is plain text, one line per path, `<path>: trusted` or
`<path>: untrusted`. No JSON flag exists, `--json` is rejected. Note it reports
the *directory* while `config ls` reports the *file*.

`mise -C <dir>` is a global flag on every one of these, so no `cd && ...`
construction is needed.

## Trust is not the drift signal

An earlier draft treated an untrusted config as one that silently fails to
apply. That is wrong, and the correction shapes the design.

`mise trust --show` reports a plain `[tools]` config as `untrusted` while
`mise ls --current --json` shows its tools `active: true`. Per `mise trust --help`,
"safe config files do not require trust: files that only contain `min_version`,
`[tools]` entries with plain version strings (or arrays of them), and `[tasks]`
without templates or tool options." Trust gates unsafe configs, meaning
templates and tool options, plus paranoid mode. For the ordinary homelab
`[tools]` file, untrusted is the normal resting state and means nothing is
wrong.

So trust status is recorded as a field for context, never as a drift trigger.
The drift class measures the effect instead. A config declares a tool that never
appears in `ls --current`. That catches the unsafe-untrusted case and every
other reason a config failed to take, without this extension modeling mise's
trust rules and going stale when they change.

## Configuration

Modeled on `netdata/netdata.ts:55-95`.

```
nodes: [{ name, ssh?: { host, user, port }, dir?, misePath? }]   # min 1
timeoutSec: 15
maxConcurrency: 8
expect: { <tool>: <version prefix> }                              # optional
```

A node with no `ssh` block is the local machine. `dir` selects which
directory's config is evaluated. mise config is directory-scoped, so without it
the question has no well-defined answer. It defaults to the swamp working
directory for local nodes and the login directory for ssh nodes, and the chosen
value is recorded on the node resource so the reading is never ambiguous.

`expect` is the single opinion, and it is opt-in. Omit it and every node is
judged only against its own config.

**`expect` matching semantics:** an expect value is satisfied when the resolved
version's dot-separated segments begin with the expect value's segments. `"22"`
matches `22.23.2`. `"22.23"` matches `22.23.2`. `"22.2"` does not match
`22.23.2`. Segment-wise, never string-prefix.

## Drift classes

| Class | Condition |
|---|---|
| `notinstalled` | In `ls --current`, `installed: false` |
| `notactive` | In `ls --current`, `installed: true`, `active: false` |
| `notineffect` | Declared in `config ls` `tools[]`, absent from `ls --current` |
| `outdated` | Present in `mise outdated --json` |
| `expected` | Active resolved version fails the `expect` match above |
| `unmeasured` | mise did not run, see below |

## Unmeasured is a first-class state

`ssh host 'mise ls --current --json'` runs a non-login shell, and mise commonly
lives in `~/.local/bin`. If that failure is allowed to look like empty output,
the host reads as "no tools configured", which reads as clean, when it was
never measured at all.

That is the same absent-reads-as-healthy defect the Fable review caught in
`dashboard`, findings 1 and 2 of `reviews/dashboard/bd9870ff….md`. So exit 127,
a "command not found" stderr, an ssh failure, and a timeout all produce
`measured: false` on the node resource and an `unmeasured` drift record. A zero
tool count is never written for a host that failed to answer.

Identity fields are nullable rather than empty-string, per `netdata.ts:107-112`.
"Never reached this host" is a different fact from "host reported an empty
version string."

## Resources

- `node-<name>` carries `name`, `measured`, `reachable`, `transport` (`local`
  or `ssh`), `error` (nullable), `miseVersion` (nullable), `dir`,
  `configCount`, `toolCount`, and a count per drift class.
- `tool-<node>-<tool>` carries `node`, `tool`, `requestedVersion`,
  `resolvedVersion`, `installPath`, `sourceType`, `sourcePath`, `installed`,
  `active`, `outdated`, `latestVersion` (nullable), and `drift` as an array of
  classes.
- `config-<node>-<slug>` carries `node`, `path`, `trusted`, `toolsDeclared`,
  `toolsInEffect`, `toolsNotInEffect`. The slug follows `dashboard`'s
  collision-safe scheme, a slug plus FNV-1a over the raw path.
- `summary` carries fleet totals: `nodes`, `nodesMeasured`, `nodesUnmeasured`,
  `tools`, and a count per drift class.

Prefix-plus-`summary` matches what `dashboard` already picks against, so a
`mise` source drops into the existing page without changing its rules.

## Transport and injection surface

Local nodes run through `Deno.Command("mise", { args: ["-C", dir, "ls", "--current", "--json"] })`,
an argv array with no shell anywhere, so there is no injection surface at all.

SSH nodes follow `netdata.ts:358-375` exactly: `ssh -o BatchMode=yes -o
ConnectTimeout=<n> -p <port> <user>@<host> <remote>`, with `stdin: "null"`,
piped stdout and stderr, and `AbortSignal.any([signal, AbortSignal.timeout(...)])`.

The remote string is where operator data lands, and it is the only place. Three
values reach it, and each is validated at schema-parse time and **rejected**
rather than silently repaired. `netdata.ts:355` strips quotes from its
interpolated URL, and a mangled path that half-works is worse than a config
error:

- `dir` must be absolute, match `[A-Za-z0-9._/-]+`, contain no `..` segment,
  and not begin with `-`.
- `misePath` takes the same charset and the same no-leading-dash rule.
- `host` and `user` must not begin with `-`, so neither can be parsed as an ssh
  option such as `-oProxyCommand=`. This is `netdata`'s existing rule.

Everything else in the remote command is a fixed literal. That is a better
position than `netdata`'s curl path, which interpolates a full URL.

## Data written

`installPath` and `sourcePath` embed the remote account's home directory, and
config paths name real project directories. This is the operator's own
infrastructure detail in their own datastore, consistent with `netdata`
recording hostnames and `truenas` recording mounts. The README documents it
under "Data written", and every README example uses placeholder paths so the
`scan-identifiers.sh` gate and the private denylist stay clean.

## Voice

Prose is inside the content hash, so per
`vault:projects/slog-bog/voice-pass-requirement.md` the voice pass happens
before the first review, not after. For a new extension that means writing the
module header, comments, `.describe()` strings, manifest description, and
`readme.vars.yaml` in the house voice from the start, so the Fable review runs
once rather than twice.

House standard for markdown, measured from the existing repo docs: no
em-dashes, no prose semicolons. Restrained rather than heavily themed, matching
the root `README.md`.

## Testing

`mise/mise_test.ts`, in the family's style, driven by a fake `mise` executable
written to a temp dir with `misePath` pointed at it. This is the `--allow-run`
pattern the `proton-pass` tests already use.

Cases: each of the six drift classes, the 127 and command-not-found split
proving `unmeasured` never renders as a zero count, `dir` and `misePath`
rejection at schema parse, `expect` segment matching including the `"22.2"`
against `22.23.2` non-match, nullable-versus-empty on `miseVersion`, and
`summary` totals agreeing with the per-node counts.

The ssh path cannot be exercised without a host, so remote-command construction
is an exported pure function tested directly on its argv output rather than
asserted through a live connection.

## Gates

Full `scripts/publish.sh mise` run: `swamp extension fmt`, `deno fmt` plus
tests, `swamp extension quality`, README drift check against the generated
file, identifier scan with the private denylist, Fable security review
committed to `reviews/mise/<hash>.md`, `swamp extension push --dry-run`, then a
stop at gate 8 for operator approval.

`SLOG_BOG_DENYLIST` must be exported before that run, or gate 5 falls back to
generic rules only and `publish.sh` warns.

Manifest mirrors its siblings: `platforms: [darwin-aarch64, linux-x86_64]`,
`dependencies: []`, `additionalFiles: [README.md, LICENSE]`, and labels along
the lines of `mise`, `toolchain`, `drift`, `fleet`, `versions`.
