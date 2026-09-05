/**
 * Tests for @jpisgeek/proton-pass.
 *
 * Exported surface only — not in the manifest, so it does not move the content
 * hash the security review is bound to.
 *
 * The property under test is the one that made this extension a publish
 * blocker in review: `pass-cli item view --output json` prints the WHOLE item
 * (secret included) on stdout, and pass-cli reports some failures on stdout
 * with exit 0. An error path that interpolated stdout would therefore put a
 * live secret into an exception string — and exception strings end up in swamp
 * run logs and reports. These tests drive a fake pass-cli that deliberately
 * prints a secret, then assert the secret never appears in the thrown error.
 *
 * Requires --allow-run --allow-write --allow-read (fake binary in a temp dir).
 */
import { assertEquals } from "jsr:@std/assert@1";
import { parse as parseYaml } from "jsr:@std/yaml@1.0.5";
import {
  canonicalId,
  classifyAbort,
  classifyCliFailure,
  CLI_VERDICTS,
  clip,
  foldTitleForDuplicates,
  parseItems,
  resolveBinary,
  vault,
} from "./proton_pass.ts";

const DEFAULT_BINARY_NAME = "pass-cli";
const SECRET = "SUPER-SECRET-VALUE-must-never-be-logged";
const HERE = import.meta.dirname!;

/**
 * Write an executable fake pass-cli emitting the given stdout/stderr/exit.
 *
 * It also appends its own argv to `<dir>/argv`, one call per line, so a test
 * can assert what this provider actually SENT rather than only what came back.
 * The put() round-trip test needs that: the bug there was in the arguments,
 * and every assertion about the response was green while it was live.
 */
async function fakeCli(
  opts: {
    stdout?: string;
    stderr?: string;
    exit?: number;
    listing?: string;
    title?: string;
    /**
     * stdout emitted through `printf`, so a test can produce bytes a TS
     * string literal cannot carry to the child intact -- notably invalid
     * UTF-8. Escapes are printf's, e.g. `\\377` for 0xFF.
     */
    stdoutPrintf?: string;
    /** Seconds to sleep before answering, for deadline and abort tests. */
    delaySec?: number;
    /** What `item create` prints as the new item's id. */
    createdId?: string;
  },
): Promise<
  {
    path: string;
    argv: () => Promise<string[][]>;
    env: () => Promise<string>;
    stdin: () => Promise<string>;
    cleanup: () => Promise<void>;
  }
> {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/pass-cli`;
  // `get` now resolves a title to exactly one LIVE item before viewing it, so
  // the fake has to answer `item list` as well as `item view`. Callers that
  // do not care about resolution get a single active item named to match.
  const listing = opts.listing ??
    listDoc([listRow({ title: opts.title ?? "Example Service" })]);
  const script = [
    "#!/bin/sh",
    // --version probe used by resolveBinary must succeed
    'if [ "$1" = "--version" ]; then echo "fake 1.0"; exit 0; fi',
    // Record argv (tab-separated, one line per invocation).
    `printf '%s\\t' "$@" >> ${dir}/argv; printf '\\n' >> ${dir}/argv`,
    // What the child actually inherited, so a test can assert on it.
    `env > ${dir}/env 2>/dev/null || true`,
    // What was fed to the child on stdin. put() sends the whole item as a
    // JSON template this way so the secret never enters argv.
    `cat > ${dir}/stdin 2>/dev/null || true`,
    opts.delaySec ? `sleep ${opts.delaySec}` : "",
    `if [ "$2" = "list" ]; then cat <<'LIST_EOF'\n${listing}\nLIST_EOF\nexit 0; fi`,
    // `item create` answers the NEW ITEM'S ID on stdout -- a real, checkable
    // success response, which put() now validates. A fake that stayed silent
    // would make every write look indeterminate.
    (opts.stdout === undefined && opts.stdoutPrintf === undefined)
      ? `if [ "$2" = "create" ]; then printf '%s\\n' '${
        opts.createdId ?? ITEM_A
      }'; fi`
      : "",
    opts.stdout ? `cat <<'STDOUT_EOF'\n${opts.stdout}\nSTDOUT_EOF` : "",
    opts.stdoutPrintf ? `printf '${opts.stdoutPrintf}'` : "",
    opts.stderr ? `cat >&2 <<'STDERR_EOF'\n${opts.stderr}\nSTDERR_EOF` : "",
    `exit ${opts.exit ?? 0}`,
  ].join("\n");
  await Deno.writeTextFile(path, script);
  await Deno.chmod(path, 0o755);
  return {
    path,
    argv: async () => {
      let raw = "";
      try {
        raw = await Deno.readTextFile(`${dir}/argv`);
      } catch { /* never invoked */ }
      return raw.split("\n").filter((l) => l.length > 0).map((l) =>
        l.split("\t").filter((a) => a.length > 0)
      );
    },
    stdin: async () => {
      try {
        return await Deno.readTextFile(`${dir}/stdin`);
      } catch {
        return "";
      }
    },
    env: async () => {
      try {
        return await Deno.readTextFile(`${dir}/env`);
      } catch {
        return "";
      }
    },
    cleanup: () => Deno.remove(dir, { recursive: true }),
  };
}

const providerFor = (
  binary: string,
  extra: Record<string, unknown> = {},
) =>
  vault.createProvider("proton", {
    vaultName: "myvault",
    defaultField: "password",
    binary,
    ...extra,
  });

/** Message of whatever the thunk threw, or "" if it returned. */
async function thrown(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "";
  } catch (e) {
    return String(e);
  }
}

// ---------------------------------------------------------------------------
// the block finding: stdout must never reach an error
// ---------------------------------------------------------------------------

Deno.test("failure with exit 0 + 'Error:' on stdout does not leak the item", async () => {
  // pass-cli's documented misbehaviour: prints the item AND an Error line,
  // exits 0.
  const cli = await fakeCli({
    stdout: `{"password":"${SECRET}"}\nError: item not found`,
    exit: 0,
  });
  try {
    const p = providerFor(cli.path);
    let msg = "";
    try {
      await p.get("Example Service/API Key");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(msg !== "", true, "expected a throw");
    assertEquals(
      msg.includes(SECRET),
      false,
      `SECRET LEAKED INTO ERROR: ${msg}`,
    );
    // The Error: line is no longer forwarded; its VERDICT is.
    assertEquals(msg.includes("item-not-found"), true, msg);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("non-zero exit with a secret on stdout withholds stdout entirely", async () => {
  const cli = await fakeCli({ stdout: viewDoc(), exit: 3 });
  try {
    const p = providerFor(cli.path);
    let msg = "";
    try {
      await p.get("Example Service/API Key");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(msg !== "", true, "expected a throw");
    assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
    // The contract moved: failures are classified rather than described, so
    // neither stdout NOR its absence is narrated. What matters is that a
    // verdict comes back and the item does not.
    assertEquals(
      /unclassified|item-not-found|session-not-usable/.test(msg),
      true,
      `expected a fixed verdict, got: ${msg}`,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("stderr is classified, never forwarded", async () => {
  // It used to be forwarded verbatim on the reasoning that stderr carries no
  // item contents. It carries something else worth withholding: pass-cli can
  // echo the arguments it was given -- vault and item names -- and whatever
  // the server said. Exception strings from here reach run logs and reports.
  const cli = await fakeCli({
    stdout: viewDoc(),
    stderr:
      "could not reach the Proton API for vault jason item my-db-password",
    exit: 1,
  });
  try {
    const p = providerFor(cli.path);
    let msg = "";
    try {
      await p.get("Example Service/API Key");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(msg.includes("network-failure"), true, msg);
    // Neither the secret nor the identifiers stderr happened to mention.
    assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
    assertEquals(msg.includes("my-db-password"), false, `NAME LEAKED: ${msg}`);
    assertEquals(
      msg.includes("could not reach"),
      false,
      `TEXT FORWARDED: ${msg}`,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("every classified verdict is a fixed string", () => {
  // The point is that the SET of things this can say is closed, so no
  // remote text can widen it.
  assertEquals(
    classifyCliFailure("not logged in", "", 1),
    "session-not-usable",
  );
  assertEquals(
    classifyCliFailure("", "Error: no such item", 1),
    "item-not-found",
  );
  assertEquals(
    classifyCliFailure("connection reset", "", 1),
    "network-failure",
  );
  assertEquals(
    classifyCliFailure("permission denied", "", 1),
    "permission-denied",
  );
  // Anything unrecognised yields a verdict, never a sample of the text.
  const v = classifyCliFailure("host quux-01 said something odd", "", 7);
  assertEquals(v, "unclassified (exit 7)");
  assertEquals(v.includes("quux-01"), false);
});

Deno.test("a keychain-locked session is reported as such, not as a raw code", async () => {
  const cli = await fakeCli({
    stderr: "User interaction is not allowed (-25308)",
    exit: 1,
  });
  try {
    const p = providerFor(cli.path);
    let msg = "";
    try {
      await p.get("Example Service/API Key");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(
      msg.includes("login Keychain"),
      true,
      `expected the actionable keychain message, got: ${msg}`,
    );
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// the happy path still works
// ---------------------------------------------------------------------------

Deno.test("get() returns the default field from a Proton-shaped item", async () => {
  const cli = await fakeCli({
    stdout: viewDoc({
      login: {},
      extra: [
        hiddenField("password", SECRET),
        { name: "note", content: { Text: "not the secret" } },
      ],
    }),
  });
  try {
    const p = providerFor(cli.path);
    // A bare title uses defaultField ("password").
    assertEquals(await p.get("Example Service"), SECRET);
    // The explicit form addresses the same field directly.
    assertEquals(await p.get("Example Service/password"), SECRET);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a key splits at the FIRST slash: title, then field", async () => {
  // "Example Service/API Key" means item "Example Service", field "API Key" —
  // documenting the parse so a caller isn't surprised by a multi-word field.
  const cli = await fakeCli({
    stdout: viewDoc({ extra: [hiddenField("API Key", SECRET)] }),
  });
  try {
    const p = providerFor(cli.path);
    assertEquals(await p.get("Example Service/API Key"), SECRET);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("get() reads a flat {name,value} custom field", async () => {
  const cli = await fakeCli({
    stdout: viewDoc({ extra: [hiddenField("apiKey", SECRET)] }),
  });
  try {
    const p = providerFor(cli.path);
    assertEquals(await p.get("Example Service/apiKey"), SECRET);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a missing field names the field, not the item contents", async () => {
  const cli = await fakeCli({
    stdout: JSON.stringify({
      item: { fields: [{ name: "other", value: SECRET }] },
    }),
  });
  try {
    const p = providerFor(cli.path);
    let msg = "";
    try {
      await p.get("Example Service/absent-field");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(msg.includes("absent-field"), true);
    assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("list() returns item titles from JSON output", async () => {
  const cli = await fakeCli({
    listing: JSON.stringify([{ title: "Item A" }, { title: "Item B" }]),
  });
  try {
    const p = providerFor(cli.path);
    assertEquals(await p.list(), ["Item A", "Item B"]);
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// trashed items are deleted items
// ---------------------------------------------------------------------------

Deno.test("list() hides trashed items", async () => {
  // `state` was in this response all along and nothing read it, so a secret
  // the operator had deleted still advertised itself as available.
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [
        { id: ITEM_A, title: "live", state: "Active" },
        { id: ITEM_B, title: "dead", state: "Trashed" },
      ],
    }),
  });
  try {
    assertEquals(await providerFor(cli.path).list(), ["live"]);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("list() collapses duplicate titles", async () => {
  // put() creates a NEW item every call rather than updating, so real vaults
  // accumulate same-titled items. Listing one key twice helps nobody.
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [
        { id: ITEM_A, title: "dup", state: "Active" },
        { id: ITEM_B, title: "dup", state: "Active" },
      ],
    }),
  });
  try {
    assertEquals(await providerFor(cli.path).list(), ["dup"]);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("get() refuses a title that only matches a trashed item", async () => {
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [{ id: ITEM_A, title: "Example Service", state: "Trashed" }],
    }),
    stdout: viewDoc(),
  });
  try {
    let msg = "";
    try {
      await providerFor(cli.path).get("Example Service");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(msg.includes("no active item"), true, msg);
    // And the trashed item's value must not come back anyway.
    assertEquals(msg.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("get() refuses an ambiguous title rather than guessing", async () => {
  // pass-cli's --item-title picks one when several match, silently. For a
  // secret, "which one did I just read" must not be unanswerable.
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [
        { id: ITEM_A, title: "Example Service", state: "Active" },
        { id: ITEM_B, title: "Example Service", state: "Active" },
      ],
    }),
    stdout: viewDoc(),
  });
  try {
    let msg = "";
    try {
      await providerFor(cli.path).get("Example Service");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(msg.includes("ambiguous"), true, msg);
    assertEquals(msg.includes("2 active items"), true, msg);
    assertEquals(msg.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an unrecognised item state does not silently hide a duplicate", async () => {
  // The listing schema used to accept any state string and test it with
  // `state.toLowerCase() === "active"`, so anything that was not the literal
  // word "active" was filed under TRASHED and dropped from the inventory.
  // That is not fail-closed. Two LIVE items share the title here and the
  // second one carries a state this provider does not know, so the row
  // vanished, the duplicate-title check saw exactly one match, and get()
  // returned a password from an item nobody chose -- silently, with no
  // ambiguity error. Assert the VALUE, not just that something throws: the
  // pre-fix code answered `SECRET`, which is the bug.
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [
        { id: ITEM_A, title: "Example Service", state: "Active" },
        { id: ITEM_B, title: "Example Service", state: "Pending" },
      ],
    }),
    stdout: viewDoc(),
  });
  try {
    let value = "";
    let msg = "";
    try {
      value = await providerFor(cli.path).get("Example Service");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(value, "", `get() returned a value: ${value === SECRET}`);
    assertEquals(msg.includes("does not recognise"), true, msg);
    assertEquals(msg.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }

  // The same guard on the human-readable fallback rows, which carry the state
  // in a different shape and were compared the same way.
  assertEquals(
    thrownSync(() => parseItems("- [A1]: Alpha (state=Pending)")) !== "",
    true,
  );
  // And the row/wrapper schemas are strict now: an envelope that merely
  // CONTAINS an items array is no longer read as a complete vault listing.
  assertEquals(
    thrownSync(() => parseItems('{"items":[],"error":"session expired"}')) !==
      "",
    true,
  );
  assertEquals(
    thrownSync(() => parseItems('[{"title":"a","state":"Active","x":1}]')) !==
      "",
    true,
  );
});

Deno.test("an item with no state field is treated as live", async () => {
  // Older pass-cli builds omit state entirely. Hiding every secret from them
  // would be a worse bug than the one being fixed.
  const cli = await fakeCli({
    listing: JSON.stringify({ items: [{ id: ITEM_A, title: "legacy" }] }),
  });
  try {
    assertEquals(await providerFor(cli.path).list(), ["legacy"]);
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// config + contract
// ---------------------------------------------------------------------------

Deno.test("configSchema requires vaultName and defaults the field", () => {
  assertEquals(vault.configSchema.safeParse({}).success, false);
  const ok = vault.configSchema.safeParse({ vaultName: "myvault" });
  assertEquals(ok.success, true);
  if (ok.success) {
    assertEquals(ok.data.defaultField, "password");
    assertEquals(ok.data.binary, "pass-cli");
  }
});

Deno.test("a missing binary produces an actionable install message", async () => {
  const p = providerFor("/nonexistent/path/to/pass-cli");
  let msg = "";
  try {
    await p.get("Example Service/API Key");
  } catch (e) {
    msg = String(e);
  }
  assertEquals(msg.includes("Proton Pass CLI"), true, `got: ${msg}`);
});

Deno.test("the provider exposes the documented vault contract", () => {
  const p = providerFor("pass-cli");
  // `put` is deliberately absent. This provider is READ-ONLY: writing was
  // responsible for 10 of 39 blocks across six review rounds, and the README
  // already told operators to create items in the Proton Pass UI and read them
  // with get(). Asserting its absence keeps it from creeping back in.
  for (const fn of ["get", "list", "getName"]) {
    assertEquals(
      typeof (p as unknown as Record<string, unknown>)[fn],
      "function",
      `missing ${fn}()`,
    );
  }
  assertEquals(
    "put" in (p as unknown as Record<string, unknown>),
    false,
    "put() is gone; this provider does not write",
  );
  assertEquals(p.getName(), "proton");
  assertEquals(vault.type, "@jpisgeek/proton-pass");
});

// ---------------------------------------------------------------------------
// the response is read at NAMED LOCATIONS, not searched
//
// The old extractValue walked every nested object looking for a key with the
// requested name and returned the first string it found. Depth-bounding it
// narrowed the blast radius and left the defect in place: a decoy one level
// down still won. These tests assert the property -- only documented locations
// are read -- rather than the depth number.
// ---------------------------------------------------------------------------

/**
 * A REALISTIC Proton id: 86 base64url characters plus `==`, which is what a
 * real vault returns for every item, share and vault id (88 characters, 64
 * encoded bytes). The old fixtures used `ID1` and `SHARE1`.
 *
 * That was not a cosmetic shortcut. Short fake ids are why a whole class of
 * defect stayed invisible: the strict base64 rules a review asked for looked
 * WRONG when applied, because the fixtures could not satisfy them, and the
 * real ids satisfy them comfortably. The same instinct as keeping SECRET
 * realistic, applied to the shapes rather than the values.
 */
const fakeId = (seed: string) => seed + "A".repeat(86 - seed.length) + "==";
const ITEM_A = fakeId("ITEMA_");
const ITEM_B = fakeId("ITEMB_");
const SHARE_A = fakeId("SHAREA_");
const SHARE_B = fakeId("SHAREB_");
const VAULT_A = fakeId("VAULTA_");

/**
 * One row of a real `item list --output json`. Every key a real row carries is
 * present, because the schema is strict and the previous fixtures omitted six
 * of them -- which is exactly why 94 passing tests coexisted with a provider
 * that could not read a single real vault.
 */
function listRow(o: {
  id?: string;
  title?: string;
  state?: string;
  shareId?: string;
  extra?: Record<string, unknown>;
} = {}): Record<string, unknown> {
  return {
    id: o.id ?? ITEM_A,
    share_id: o.shareId ?? SHARE_A,
    vault_id: VAULT_A,
    state: o.state ?? "Active",
    flags: [],
    create_time: "2026-01-01T00:00:00Z",
    modify_time: "2026-01-01T00:00:00Z",
    title: o.title ?? "Example Service",
    item_type: "login",
    ...(o.extra ?? {}),
  };
}
const listDoc = (rows: Record<string, unknown>[]) =>
  JSON.stringify({ items: rows });

/**
 * A real `item view --output json` document. The value lives at
 * `item.content.content.<Variant>.<slot>` and custom fields at
 * `item.content.extra_fields` -- two containers deeper than the fixtures this
 * replaces believed.
 */
function viewDoc(o: {
  id?: string;
  shareId?: string;
  state?: string;
  title?: string;
  note?: string;
  variant?: string;
  login?: Record<string, unknown>;
  extra?: unknown[];
  contentOverride?: Record<string, unknown>;
  itemOverride?: Record<string, unknown>;
} = {}): string {
  const content: Record<string, unknown> = o.contentOverride ?? {
    title: o.title ?? "Example Service",
    note: o.note ?? "",
    item_uuid: "uuid",
    content: { [o.variant ?? "Login"]: o.login ?? { password: SECRET } },
    extra_fields: o.extra ?? [],
  };
  return JSON.stringify({
    item: {
      id: o.id ?? ITEM_A,
      share_id: o.shareId ?? SHARE_A,
      vault_id: VAULT_A,
      content,
      state: o.state ?? "Active",
      flags: [],
      create_time: "2026-01-01T00:00:00Z",
      modify_time: "2026-01-01T00:00:00Z",
      ...(o.itemOverride ?? {}),
    },
    attachments: [],
  });
}

/** A custom field as `content.extra_fields` actually carries it. */
const hiddenField = (name: string, value: string) => ({
  name,
  content: { Hidden: value },
});

const DECOY = "DECOY-VALUE-FROM-SOMEWHERE-ELSE-IN-THE-RESPONSE";

Deno.test("a shallow decoy sharing the field name is never returned as the secret", async () => {
  const cli = await fakeCli({
    stdout: JSON.stringify({
      // Documented location: the item's field list. It does NOT hold
      // "password".
      fields: [{ name: "other", value: "not it" }],
      // Undocumented location, one level deep -- well inside the old bound.
      metadata: { password: DECOY },
    }),
  });
  try {
    const msg = await thrown(() =>
      providerFor(cli.path).get("Example Service")
    );
    assertEquals(msg !== "", true, "expected a refusal, got a value");
    assertEquals(msg.includes(DECOY), false, `DECOY LEAKED: ${msg}`);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a decoy beside a documented location is refused", async () => {
  const cli = await fakeCli({
    stdout: JSON.stringify({
      item: { fields: [{ name: "other", value: "not it" }] },
      diagnostics: { lastResponse: { password: DECOY } },
    }),
  });
  try {
    const msg = await thrown(() =>
      providerFor(cli.path).get("Example Service/password")
    );
    assertEquals(msg !== "", true, "expected a refusal, got a value");
    assertEquals(msg.includes(DECOY), false, `DECOY LEAKED: ${msg}`);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an item shape matching no documented location is refused, not mined", async () => {
  const cli = await fakeCli({
    // An array whose entries are not {name,...} field entries.
    // A document with no `content` container at all is not an item, however
    // much it looks like one from the outside.
    stdout: JSON.stringify({
      item: { id: ITEM_A, share_id: SHARE_A, state: "Active" },
      attachments: [],
    }),
  });
  try {
    const msg = await thrown(() =>
      providerFor(cli.path).get("Example Service")
    );
    assertEquals(msg.includes("does not recognise"), true, msg);
    assertEquals(msg.includes(DECOY), false, `DECOY LEAKED: ${msg}`);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("the documented locations still resolve", async () => {
  // The refusals above must not have taken the working shapes with them.
  // The real ones, not the invented ones. A value reaches a caller from
  // exactly two places: the typed block inside `content.content`, and a custom
  // field in `content.extra_fields`. The four shapes listed here before -- a
  // bare field array, a top-level `password`, a `login` block, a top-level
  // `fields[]` -- occur in no pass-cli response.
  const shapes: [string, string][] = [
    ["typed Login slot", viewDoc({ login: { password: SECRET } })],
    [
      "custom field",
      viewDoc({ login: {}, extra: [hiddenField("password", SECRET)] }),
    ],
  ];
  for (const [what, shape] of shapes) {
    const cli = await fakeCli({ stdout: shape });
    try {
      assertEquals(
        await providerFor(cli.path).get("Example Service"),
        SECRET,
        what,
      );
    } finally {
      await cli.cleanup();
    }
  }
});

// ---------------------------------------------------------------------------
// the item list is parsed strictly
// ---------------------------------------------------------------------------

/** Message of whatever a synchronous thunk threw, or "" if it returned. */
function thrownSync(fn: () => unknown): string {
  try {
    fn();
    return "";
  } catch (e) {
    return String(e);
  }
}

Deno.test("blank item-list output is an error, not an empty vault", () => {
  // `--output json` answers an empty vault with `[]`, never with nothing.
  // Returning [] made a broken call and "you have no secrets" the same
  // answer, and the second is a fact a caller acts on.
  assertEquals(thrownSync(() => parseItems("")) !== "", true);
  assertEquals(thrownSync(() => parseItems("   \n  \n")) !== "", true);
  // The genuinely-empty answers still parse.
  assertEquals(parseItems("[]"), []);
  assertEquals(parseItems('{"items":[]}'), []);
});

Deno.test("list() surfaces a blank listing rather than reporting no secrets", async () => {
  const cli = await fakeCli({ listing: "" });
  try {
    const msg = await thrown(() => providerFor(cli.path).list());
    assertEquals(msg !== "", true, "expected a refusal, got a listing");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("the human-readable listing format is refused, not parsed", () => {
  // This test used to assert the text fallback parsed every nonblank row. The
  // fallback is gone, and the row format is why: it ended with an optional
  // `(state=Trashed)` suffix, so an item whose TITLE ends that way was
  // indistinguishable from state metadata. A caller decides whether a
  // credential is still valid on that answer.
  //
  // The ambiguity, demonstrated: this row is either an item named
  // "Alpha (state=Trashed)" that is live, or an item named "Alpha" that is
  // trashed. Nothing in the format can say which.
  const ambiguous = "- [A1]: Alpha (state=Trashed)";
  assertEquals(thrownSync(() => parseItems(ambiguous)) !== "", true);

  // Refusal is not selective: no text listing parses, well-formed or not.
  const wellFormed =
    "- [A1]: Alpha (state=Active)\n- [B2]: Beta (state=Trashed)";
  assertEquals(thrownSync(() => parseItems(wellFormed)) !== "", true);

  // JSON still parses, so the refusal is about the format and not the content.
  const json = JSON.stringify([
    // The REAL casing. pass-cli emits "Active" and "Trashed"; this fixture
    // used lowercase, which only parsed because isActiveState() case-folded --
    // and case-folding is what let a response differing from the documented
    // enum read as live instead of being refused.
    { id: ITEM_A, title: "Alpha", state: "Active" },
    { id: ITEM_B, title: "Beta", state: "Trashed" },
  ]);
  assertEquals(parseItems(json).length, 2);
  assertEquals(parseItems(json)[1].active, false);
});

// ---------------------------------------------------------------------------
// an item with no id cannot be addressed, so it is refused
// ---------------------------------------------------------------------------

Deno.test("get() fails closed when the matching row carries no item id", async () => {
  // The id used to be defaulted to "", which typechecked and then silently
  // disabled the exact-address step: the falsy id fell through to
  // `--item-title`, the selector this provider exists to stop trusting.
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [{ title: "Example Service", state: "Active" }],
    }),
    stdout: viewDoc(),
  });
  try {
    const msg = await thrown(() =>
      providerFor(cli.path).get("Example Service")
    );
    assertEquals(msg !== "", true, "expected a refusal, got a value");
    assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
    assertEquals(msg.includes("--item-title"), true, msg);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("--item-title is never sent to pass-cli", async () => {
  // The property, not the message: whatever get() resolves, the selector it
  // hands the CLI addresses exactly one item by id.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    assertEquals(await providerFor(cli.path).get("Example Service"), SECRET);
    const calls = await cli.argv();
    for (const call of calls) {
      assertEquals(
        call.includes("--item-title"),
        false,
        `--item-title sent: ${call.join(" ")}`,
      );
    }
    // `--option=value`, so the id travels INSIDE its own argv entry. Passed as
    // a separate entry, a value beginning with `-` is free to be read as a
    // flag by pass-cli's own parser -- avoiding a shell stops shell injection,
    // not argument injection.
    const view = calls.find((c) => c[1] === "view")!;
    assertEquals(
      view.includes(`--item-id=${ITEM_A}`),
      true,
      view.join(" "),
    );
    assertEquals(
      view.some((a) => a === "--item-id"),
      false,
      "the id was passed as a separate argument, not joined",
    );
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// a malformed pass:// URI is refused, not passed through
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// put(): accept a key, or round-trip it. Never both wrong.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// cancellation
// ---------------------------------------------------------------------------

Deno.test("caller cancellation outranks the timeout when both have fired", () => {
  // The old order asked the deadline first, so the common case -- a caller
  // giving up on a call that was also slow -- was reported as a Proton
  // timeout, sending whoever read the log to the wrong system.
  assertEquals(classifyAbort(true, true), "cancelled");
  assertEquals(classifyAbort(true, false), "cancelled");
  assertEquals(classifyAbort(false, true), "timeout");
  assertEquals(classifyAbort(false, false), "exec-failed");
});

Deno.test("cancellation is honoured during binary resolution", async () => {
  // Resolution ran BEFORE the signal was consulted, so a caller that had
  // already given up still waited out up to four 5s --version probes and was
  // then told the binary could not be found.
  // A VALID config, because `binary` is now validated at construction: an
  // unsanctioned bare name fails there and the call never reaches the
  // cancellation check this test is about.
  const p = providerFor(DEFAULT_BINARY_NAME);
  const msg = await thrown(() => p.get("Example Service", AbortSignal.abort()));
  assertEquals(msg.includes("cancelled"), true, `got: ${msg}`);
  assertEquals(msg.includes("Could not find"), false, `got: ${msg}`);
});

Deno.test("a caller signal reaches the pass-cli process", async () => {
  // Proves the signal is threaded from get()/list()/put() and not merely
  // accepted by run(): with no threading the fake answers happily and the
  // secret comes back.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    const p = providerFor(cli.path);
    for (
      const call of [
        () => p.get("Example Service", AbortSignal.abort()),
        () => p.list(AbortSignal.abort()),
        () => p.get("Example Service", AbortSignal.abort()),
      ]
    ) {
      const msg = await thrown(call);
      assertEquals(msg.includes("cancelled"), true, `got: ${msg}`);
      assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
    }
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// every interpolated string in an error is bounded
// ---------------------------------------------------------------------------

Deno.test("no error message carries an unbounded caller-supplied string", async () => {
  // Secret keys, item titles, field names and the vault name all land in swamp
  // run logs. Bounding whichever one was noticed first only moves which string
  // floods the log, so all of them are bounded at one place.
  const huge = "X".repeat(20_000);
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [{ id: ITEM_A, title: "other", state: "Active" }],
    }),
    stdout: viewDoc(),
  });
  try {
    const cases: (() => Promise<unknown>)[] = [
      () => providerFor(cli.path).get(huge),
      () => providerFor(cli.path).get(`${huge}/${huge}`),
      () => providerFor(cli.path).get(huge),
      () => providerFor(cli.path).get(`${huge}/f`),
      () => providerFor(cli.path, { vaultName: huge }).get(huge),
      () => providerFor(cli.path).get(`Example Service/${huge}`),
    ];
    for (const [i, c] of cases.entries()) {
      const msg = await thrown(c);
      assertEquals(msg !== "", true, `case ${i}: expected a throw`);
      assertEquals(
        msg.length < 2000,
        true,
        `case ${i}: error carried ${msg.length} chars`,
      );
      assertEquals(msg.includes(huge), false, `case ${i}: unbounded string`);
    }
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// gate finding 1: item responses are validated strictly, and a value comes
// from a NAMED location or not at all
//
// The previous version parsed the item body with `.catchall(z.unknown())`, so
// nearly any object was accepted as an item; read `body[field]` with the
// CALLER'S field name, so any top-level string could be requested as the
// secret; and returned the first string in a `content` wrapper whatever the
// wrapper key was called. Each test below returns a WRONG VALUE rather than
// throwing when the guard is absent, so `value` is captured explicitly:
// asserting only that something was thrown would pass for the wrong reason.
// ---------------------------------------------------------------------------

/** Run get() and report both outcomes, since the bug returns rather than throws. */
async function getOutcome(
  p: { get: (k: string) => Promise<string> },
  key: string,
): Promise<{ value: string; error: string }> {
  try {
    return { value: await p.get(key), error: "" };
  } catch (e) {
    return { value: "", error: String(e) };
  }
}

Deno.test("an unrecognised content wrapper is refused, not skimmed for a string", async () => {
  // Proton puts a LABEL beside the value for some field types. The old reader
  // took `Object.values(content)`'s first string, and JSON key order is the
  // serialiser's choice — so this response handed the label back as the
  // secret, and the caller authenticated with "prod-db".
  const cli = await fakeCli({
    stdout: JSON.stringify({
      item: {
        fields: [{
          name: "password",
          content: { Label: "prod-db", Hidden: SECRET },
        }],
      },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' as the secret`);
    assertEquals(r.error !== "", true, "expected a refusal");
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("two populated content wrappers are refused rather than ordered", async () => {
  const cli = await fakeCli({
    stdout: JSON.stringify({
      item: {
        fields: [{
          name: "password",
          content: { Text: DECOY, Hidden: SECRET },
        }],
      },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' as the secret`);
    assertEquals(r.error !== "", true, "expected a refusal");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an arbitrary top-level string cannot be requested as a secret", async () => {
  // `body[field]` with the caller's own field name, against a catchall schema,
  // meant every top-level string in every response was retrievable by asking
  // for it by name. A custom field lives in `fields[]`; the body itself has a
  // closed set of value slots and `shareId` is not one of them.
  const cli = await fakeCli({
    stdout: JSON.stringify({
      item: {
        shareId: "SHARE-ID-IS-NOT-A-SECRET",
        fields: [{ name: "other", value: "not it" }],
      },
    }),
  });
  try {
    const r = await getOutcome(
      providerFor(cli.path),
      "Example Service/shareId",
    );
    assertEquals(r.value, "", `returned '${r.value}' as the secret`);
    assertEquals(r.error !== "", true, "expected a refusal");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an error envelope that happens to carry a password is refused", async () => {
  // The exact shape the schema comment warns about. Under the catchall this
  // parsed as an item and `body.password` came back as the secret, with
  // nothing anywhere to show that the lookup had actually failed.
  const cli = await fakeCli({
    stdout: JSON.stringify({ error: "item view failed", password: DECOY }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' as the secret`);
    assertEquals(r.error.includes("does not recognise"), true, r.error);
    assertEquals(r.error.includes(DECOY), false, `DECOY LEAKED: ${r.error}`);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a response with no container and no value slot is not an item", async () => {
  // `{}` and a bare list row pass a key check and hold nothing. Reporting
  // "field not present" for them blames the operator's field name for a
  // response that was never an item.
  for (
    const shape of [{}, { id: ITEM_A, title: "Example Service" }]
  ) {
    const cli = await fakeCli({ stdout: JSON.stringify(shape) });
    try {
      const r = await getOutcome(providerFor(cli.path), "Example Service");
      assertEquals(r.value, "", "returned a value from a non-item");
      assertEquals(r.error.includes("does not recognise"), true, r.error);
    } finally {
      await cli.cleanup();
    }
  }
});

Deno.test("two documented locations disagreeing about one field is refused", async () => {
  // Precedence (`fields[] ?? body ?? login`) resolves this silently, and
  // whichever location a planted value can be made to occupy wins. For a
  // secret, "the response does not say" must not be answered with a guess.
  const cases: string[] = [
    // the same custom field name twice
    viewDoc({
      login: {},
      extra: [hiddenField("password", DECOY), hiddenField("password", SECRET)],
    }),
    // a custom field disagreeing with the typed slot of the same name
    viewDoc({
      login: { password: SECRET },
      extra: [hiddenField("password", DECOY)],
    }),
  ];
  for (const shape of cases) {
    const cli = await fakeCli({ stdout: shape });
    try {
      const r = await getOutcome(providerFor(cli.path), "Example Service");
      assertEquals(r.value, "", `returned '${r.value}' from an ambiguous item`);
      // Two refusals reach here now -- duplicated NAMES in the field array are
      // caught while the array is read, disagreeing LOCATIONS when the
      // candidates are compared -- and the shared clause is what both must
      // say. Asserting the narrower "more than one value" passed the first
      // case only by accident of which guard happened to fire.
      assertEquals(
        r.error.includes("refusing to choose between them"),
        true,
        r.error,
      );
      assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
      assertEquals(r.error.includes(DECOY), false, "DECOY LEAKED");
    } finally {
      await cli.cleanup();
    }
  }
});

// ---------------------------------------------------------------------------
// gate finding 2: the configured timeout covers binary RESOLUTION
// ---------------------------------------------------------------------------

Deno.test("timeoutSec bounds binary resolution, not just the pass-cli call", async () => {
  // Resolution probes up to four executables with `--version` at 5s each. It
  // used to receive only the CALLER'S signal, never the configured deadline,
  // so a wedged pass-cli on PATH burned a full probe timeout while the
  // operator's `timeoutSec: 1` had already expired — the bound they set did
  // not bound the work.
  //
  // Timed rather than asserted on the message: both versions end with
  // "not located within 1s". The defect is that the unfixed one takes ~5s to
  // say it, and with all four probes wedged, ~20s.
  const dir = await Deno.makeTempDir();
  const wedged = `${dir}/pass-cli`;
  await Deno.writeTextFile(wedged, "#!/bin/sh\nsleep 30\n");
  await Deno.chmod(wedged, 0o755);
  const oldPath = Deno.env.get("PATH") ?? "";
  Deno.env.set("PATH", `${dir}:${oldPath}`);
  try {
    // A BARE name: an absolute path short-circuits resolution entirely, so it
    // would not exercise the probe walk at all. It must be the SANCTIONED bare
    // name too -- any other is now refused before any probe runs -- so the
    // wedged fixture is called `pass-cli` and its directory is first on PATH.
    const p = providerFor("pass-cli", { timeoutSec: 1 });
    const started = performance.now();
    const msg = await thrown(() => p.get("Example Service"));
    const elapsed = performance.now() - started;
    assertEquals(msg.includes("within 1s"), true, `got: ${msg}`);
    assertEquals(
      elapsed < 3000,
      true,
      `resolution ran ${Math.round(elapsed)}ms past a 1s deadline`,
    );
  } finally {
    Deno.env.set("PATH", oldPath);
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a caller cancellation mid-resolution is still 'cancelled', not a timeout", async () => {
  // The other half of the same fix. Resolution now receives the COMBINED
  // signal, which cannot say which source fired — so run() re-decides from the
  // two it holds. Get that wrong and a caller giving up is reported as the
  // operator's timeoutSec expiring, which sends whoever reads the log to the
  // wrong system entirely. (The timing test above covers the timeout half:
  // it asserts the message says "within 1s" rather than "cancelled".)
  const dir = await Deno.makeTempDir();
  const wedged = `${dir}/pass-cli`;
  await Deno.writeTextFile(wedged, "#!/bin/sh\nsleep 30\n");
  await Deno.chmod(wedged, 0o755);
  const oldPath = Deno.env.get("PATH") ?? "";
  Deno.env.set("PATH", `${dir}:${oldPath}`);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 100);
  try {
    const p = providerFor("pass-cli", {
      timeoutSec: 30,
    });
    const msg = await thrown(() => p.get("Example Service", ac.signal));
    assertEquals(msg.includes("cancelled"), true, `got: ${msg}`);
    assertEquals(msg.includes("within 30s"), false, `got: ${msg}`);
  } finally {
    clearTimeout(timer);
    Deno.env.set("PATH", oldPath);
    await Deno.remove(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// gate finding 3: control characters never reach a run log
// ---------------------------------------------------------------------------

Deno.test("clip() escapes control characters instead of passing them through", () => {
  // Bounding a string is not the same as making it safe to write down: a
  // 30-character key is well inside the length bound and can still end a log
  // line, start a new one, or drive a terminal.
  assertEquals(clip("a\nb").includes("\n"), false, clip("a\nb"));
  assertEquals(clip("a\nb"), "a\\x0ab");
  assertEquals(clip("a\x00b"), "a\\x00b");
  assertEquals(clip("a\x1b[2Jb"), "a\\x1b[2Jb");
  assertEquals(clip("a\u202eb"), "a\\u202eb");
  assertEquals(clip("plain text"), "plain text");
  // And the bound still holds AFTER escaping, which expands 1 char to 4.
  const many = "\n".repeat(500);
  assertEquals(clip(many).length < 200, true, `${clip(many).length} chars`);
});

Deno.test("a secret key carrying a newline is refused before pass-cli is invoked", async () => {
  // The attack: the key is interpolated into the "not found" error, exception
  // strings land in swamp run logs, so a newline in the key writes a SECOND
  // line into the log that reads exactly like a real one.
  const forged = "Example Service\n2026-01-01 00:00:00 INFO vault.get ok";
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    const msg = await thrown(() => providerFor(cli.path).get(forged));
    assertEquals(msg !== "", true, "expected a refusal");
    assertEquals(msg.includes("\n"), false, `FORGED LOG LINE: ${msg}`);
    assertEquals(
      msg.includes("\\x0a"),
      true,
      `expected an escaped key: ${msg}`,
    );
    // The guard RUNS, and runs first: nothing was sent to the CLI at all.
    assertEquals(
      (await cli.argv()).length,
      0,
      "pass-cli was invoked with a control-character key",
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("terminal escapes and NULs in a key never reach the error text", async () => {
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    for (
      const bad of [
        "Item\x1b[2J\x1b[1;1H",
        "Item\x00truncated",
        "Item\u202eelbisrever",
        "Item\u2028line",
      ]
    ) {
      for (
        const call of [
          () => providerFor(cli.path).get(bad),
          () => providerFor(cli.path).get(bad),
        ]
      ) {
        const msg = await thrown(call);
        assertEquals(msg !== "", true, `expected a refusal for ${bad.length}`);
        assertEquals(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(msg), false, msg);
        assertEquals(msg.includes(SECRET), false, "SECRET LEAKED");
      }
    }
    assertEquals((await cli.argv()).length, 0, "pass-cli was invoked anyway");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("config values carrying control characters are rejected at parse", () => {
  // vaultName is interpolated into nearly every error this provider raises,
  // and binary/defaultField into several. Config is the other half of the
  // locator guard: caught once at load rather than at the first lookup.
  for (const key of ["vaultName", "defaultField", "binary"]) {
    const cfg: Record<string, unknown> = { vaultName: "myvault" };
    cfg[key] = "value\ninjected";
    assertEquals(
      vault.configSchema.safeParse(cfg).success,
      false,
      `${key} accepted a newline`,
    );
  }
  // The ordinary config still parses.
  assertEquals(
    vault.configSchema.safeParse({ vaultName: "myvault" }).success,
    true,
  );
});

// ---------------------------------------------------------------------------
// gate finding 4: the local executable path is never published
// ---------------------------------------------------------------------------

/** Every message in an error's `cause` chain — loggers print all of them. */
function causeChain(e: unknown): string {
  const parts: string[] = [];
  let cur: unknown = e;
  for (let depth = 0; depth < 16 && cur instanceof Error; depth++) {
    parts.push(cur.message);
    cur = cur.cause;
  }
  return parts.join("\n");
}

async function errorOf(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return undefined;
  } catch (e) {
    return e;
  }
}

Deno.test("a configured executable path never reaches an error, cause chain included", async () => {
  // Exception strings from this provider are written to swamp run logs and
  // run reports, which are read by people who have no business learning the
  // filesystem layout of the host swamp runs on. `binary:` is routinely an
  // absolute path inside a home directory or a private tooling tree.
  //
  // The cause chain matters as much as the message: Deno's spawn rejection
  // quotes the path it failed to run, and console.error prints the chain.
  const dir = await Deno.makeTempDir();
  const bogus = `${dir}/private-tooling/pass-cli`;
  try {
    const e = await errorOf(() => providerFor(bogus).get("Example Service"));
    assertEquals(e !== undefined, true, "expected a throw");
    const text = causeChain(e);
    assertEquals(text.includes(bogus), false, `PATH LEAKED: ${text}`);
    assertEquals(text.includes(dir), false, `PATH LEAKED: ${text}`);
    assertEquals(
      text.includes("private-tooling"),
      false,
      `PATH LEAKED: ${text}`,
    );
    // Still actionable without naming anything local.
    assertEquals(text.includes("Proton Pass CLI"), true, text);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a not-found binary names neither the configured name nor the search paths", async () => {
  // The other publication site: the message raised when the probe walk finds
  // nothing used to quote the configured value AND the absolute install
  // prefixes it had just tried.
  //
  // Driven through resolveBinary with an explicit candidate list rather than
  // through get(): on a machine that HAS pass-cli installed, a bare name
  // resolves to the real CLI, so a test going the long way round would miss
  // this branch entirely on the developer's own laptop — and would hand a
  // live credential tool a vault name while missing it.
  const name = "pass-cli-absent-from-this-host";
  const paths = [
    "/opt/homebrew/bin/pass-cli-absent-from-this-host",
    "/usr/local/bin/pass-cli-absent-from-this-host",
  ];
  const e = await errorOf(() => resolveBinary(name, undefined, paths));
  assertEquals(e !== undefined, true, "expected a throw");
  const text = causeChain(e);
  assertEquals(text.includes("Could not find"), true, text);
  assertEquals(text.includes(name), false, `NAME LEAKED: ${text}`);
  for (const p of paths) {
    assertEquals(text.includes(p), false, `PATH LEAKED: ${text}`);
  }
  assertEquals(text.includes("/opt/homebrew"), false, `PATH LEAKED: ${text}`);
  assertEquals(text.includes("/usr/local"), false, `PATH LEAKED: ${text}`);
});

// ---------------------------------------------------------------------------
// the README describes the code that ships
// ---------------------------------------------------------------------------

const README = await Deno.readTextFile(`${HERE}/README.md`);

Deno.test("the README's verdict list is exactly the set the code can produce", () => {
  // The Security section used to open by saying error messages carry pass-cli's
  // stderr or its `Error:` lines, and close by saying nothing pass-cli wrote is
  // forwarded. Both cannot be true, and a reader acting on the first would have
  // assumed remote text is available for debugging when it is not.
  const listed = new Set(
    [...README.matchAll(/`([a-z][a-z-]*)`/g)]
      .map((m) => m[1])
      .filter((w) => (CLI_VERDICTS as readonly string[]).includes(w)),
  );
  assertEquals(
    [...listed].sort(),
    [...CLI_VERDICTS].sort(),
    "the README's verdict list has drifted from CLI_VERDICTS",
  );
  // And the contradicting claim must not come back.
  const sec = README.slice(README.indexOf("## Security"));
  assertEquals(
    /carry pass-cli's stderr|stderr or its `Error:` lines only/.test(sec),
    false,
    "README claims stderr is forwarded; the code classifies it instead",
  );
});

Deno.test("the README example is a configuration that works as written", () => {
  const fence = /```yaml\n([\s\S]*?)```/.exec(README);
  assertEquals(fence !== null, true, "no yaml example in the README");
  const body = fence![1];

  // Every config key must sit UNDER `config:`, including any shown commented
  // out. `deno fmt` reformats this block on every regeneration and dedents a
  // trailing comment to column 0 -- which is how `binary` ended up outside
  // `config`, so uncommenting the documented example produced the wrong shape.
  const configKeys = Object.keys(
    (vault.configSchema as unknown as { shape: Record<string, unknown> }).shape,
  );
  for (const line of body.split("\n")) {
    const m = /^(\s*)(?:#\s*)?([A-Za-z][A-Za-z0-9_]*)\s*:/.exec(line);
    if (!m) continue;
    if (!configKeys.includes(m[2])) continue;
    assertEquals(
      m[1].length > 0,
      true,
      `config key '${m[2]}' sits at column 0, outside config: ${line}`,
    );
  }

  // And the example as a whole parses to a config this provider accepts.
  const doc = parseYaml(body) as Record<string, unknown>;
  assertEquals(Object.keys(doc).sort(), ["config", "name", "type"]);
  assertEquals(doc.type, vault.type);
  assertEquals(vault.configSchema.safeParse(doc.config).success, true);
});

Deno.test("the README states the trades the code makes", () => {
  // An undocumented trade is a finding next round. Each of these is a
  // deliberate choice the code makes and refuses to hide.
  // Wrapped by `deno fmt` at render time, so match on normalised whitespace
  // rather than on where the line breaks happened to land.
  const prose = README.slice(README.indexOf("## Caveats")).replace(/\s+/g, " ");
  for (
    const [what, re] of [
      [
        "binary identity is trusted",
        /nothing verifies its ownership, signature or digest/i,
      ],
      // put() is gone entirely, so the trade goes with it. What the README now
      // has to state is the REMOVAL and its cost -- a documented trade-off
      // that quietly stops being true is the same defect as an undocumented
      // one, and so is a documented feature that no longer exists.
      ["the provider is read-only", /THIS PROVIDER IS READ-ONLY/],
      [
        "titles break on rename",
        /renaming an item in the Proton Pass UI breaks any\s+key/i,
      ],
      [
        "absent state means live",
        /`state` field is absent is treated as live/i,
      ],
      // Gone with the URI form: there is no cross-vault address left to pass
      // through unchecked, which is the point of removing it.

      ["secret keys appear in errors", /Secret keys appear in errors/],
      ["responses are read at named locations", /named\s+locations only/i],
    ] as [string, RegExp][]
  ) {
    assertEquals(re.test(prose), true, `README does not state: ${what}`);
  }
});

Deno.test("a flooding CLI is refused, not buffered to exhaustion", async () => {
  // .output() buffered both streams to completion with no limit, so the CHILD
  // chose how much memory this process allocated. The per-call deadline did not
  // help -- a program emits gigabytes well inside 30 seconds.
  //
  // Written inline rather than through fakeCli(): this needs a script that
  // floods, which that helper does not model, and twenty other tests depend on
  // its current shape.
  //
  // `head -c` bounds the writer so a regression fails fast rather than by
  // hanging the suite. The assertion is that the read is REFUSED -- a truncated
  // JSON document is a different document, and this provider refuses
  // unreadable responses rather than mining them.
  const dir = await Deno.makeTempDir();
  const bin = `${dir}/pass-cli-flooding-for-tests`;
  await Deno.writeTextFile(
    bin,
    "#!/bin/sh\nyes EXAMPLE_FLOOD | head -c 8000000\n",
  );
  await Deno.chmod(bin, 0o755);
  try {
    const p = providerFor(bin);
    const msg = await thrown(() => p.get("Example Service"));
    assertEquals(
      msg.includes("more output than this provider will read"),
      true,
      `got: ${msg}`,
    );
    // The refusal names no CLI text and no path.
    assertEquals(msg.includes("EXAMPLE_FLOOD"), false, `LEAKED: ${msg}`);
    assertEquals(msg.includes(bin), false, `PATH LEAKED: ${msg}`);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("titles that render identically are ambiguous, not distinct", () => {
  // Found by an adversarial pass, and it produced a WRONG SECRET rather than
  // an error. get() compared titles with `===`, so two items whose titles
  // render identically were two different titles: each matched exactly one
  // item, the duplicate refusal never fired, and the caller was handed a
  // confidently wrong value. Which one arrived depended on the byte sequence
  // in the model YAML, so an editor or a clipboard round-trip could flip it.
  //
  // The fold is for DETECTION only. Selection still requires an exact match,
  // so a collision refuses rather than resolving to either candidate.
  // Typed as string, not as literals: TypeScript can prove these two literals
  // differ and rejects the comparison as unintentional -- which is exactly the
  // precondition being asserted, so the types are widened to let it run.
  const nfd: string = "prod-caf\u0065\u0301"; // e + combining acute
  const nfc: string = "prod-caf\u00e9"; // precomposed é
  assertEquals(nfd === nfc, false, "precondition: distinct as JS strings");
  assertEquals(
    foldTitleForDuplicates(nfd),
    foldTitleForDuplicates(nfc),
    "composition twins must fold together",
  );

  // The other two demonstrated twins.
  assertEquals(
    foldTitleForDuplicates("prod-db "),
    foldTitleForDuplicates("prod-db"),
    "trailing whitespace must fold",
  );
  assertEquals(
    foldTitleForDuplicates("ci-token\uFE0E"),
    foldTitleForDuplicates("ci-token"),
    "variation selectors must fold",
  );

  // Distinct titles must NOT fold together, or get() starts refusing lookups
  // that are legitimately unambiguous.
  assertEquals(
    foldTitleForDuplicates("prod-db") === foldTitleForDuplicates("prod-db2"),
    false,
  );
  assertEquals(
    foldTitleForDuplicates("Prod") === foldTitleForDuplicates("prod"),
    false,
    "case is meaningful and must not be folded away",
  );

  // Disclosed residual: cross-script confusables are NOT folded. Catching them
  // needs Unicode's confusables table. Asserted so the gap is a recorded fact
  // rather than an assumption, and so this test fails loudly if that changes.
  assertEquals(
    foldTitleForDuplicates("deploy-a-key") ===
      foldTitleForDuplicates("deploy-\u0430-key"),
    false,
    "Cyrillic homoglyph is a known, documented residual",
  );
});

// ---------------------------------------------------------------------------
// Guards that a mutation pass found UNPROTECTED.
//
// A mutation audit deleted each of the ten security guards in this file one at
// a time and re-ran the suite. Seven survived: the suite stayed 56/56 green
// with the protection gone. A guard no test can see is a guard a future
// refactor removes silently, and this codebase has been bitten by exactly that
// -- a fixture apiKey of "k", a value the redaction code could never have
// redacted, let a real redaction hole survive a fully passing suite.
//
// Each test below was confirmed to FAIL against the code with its guard
// reverted.
// ---------------------------------------------------------------------------

Deno.test("a non-default binary name never falls back to pass-cli's paths", async () => {
  // THE LIVE ONE. With this guard deleted, resolveBinary() for a name that is
  // not "pass-cli" walked the standard install locations and returned the
  // operator's REAL credential tool -- so secret locators and put() values went
  // to a program nobody configured, and the suite stayed green.
  //
  // No explicit candidate list here, deliberately: the pre-existing test that
  // looks like it covers this passes one, which is the case the guard exempts,
  // so it never reached the branch.
  const msg = await thrown(() =>
    resolveBinary("pass-cli-beta-does-not-exist-on-this-host")
  );
  assertEquals(msg !== "", true, "expected a refusal, not a substitution");
  assertEquals(
    msg.includes("must be either the bare name"),
    true,
    `got: ${msg}`,
  );
  // And the refusal must not name a path, which is the other property here.
  assertEquals(msg.includes("/opt/"), false, `PATH LEAKED: ${msg}`);
  assertEquals(msg.includes("/usr/"), false, `PATH LEAKED: ${msg}`);
});

Deno.test("a row whose title and name disagree is refused", () => {
  // No fixture anywhere set `name`, so this guard was invisible to the suite.
  const rows = JSON.stringify([{ id: ITEM_A, title: "Alpha", name: "Beta" }]);
  assertEquals(thrownSync(() => parseItems(rows)) !== "", true);
  // Agreeing aliases are still fine -- the guard must not reject valid rows.
  const ok = JSON.stringify([{ id: ITEM_A, title: "Alpha", name: "Alpha" }]);
  assertEquals(parseItems(ok).length, 1);
});

Deno.test("two rows sharing an id are refused", () => {
  // Untested, and it is the guard that stops item selection being decided by
  // listing order: an active and a trashed row sharing an id authorised or
  // refused according to which the CLI happened to print first.
  const dup = JSON.stringify([
    // Real casing, and a real id shape: this test asserts the DUPLICATE-ID
    // refusal, so it must not pass for the incidental reason that its rows
    // were malformed in some other way.
    { id: ITEM_A, title: "Alpha", state: "Active" },
    { id: ITEM_A, title: "Beta", state: "Trashed" },
  ]);
  assertEquals(thrownSync(() => parseItems(dup)) !== "", true);
});

Deno.test("blank and whitespace-only titles are refused", () => {
  for (const bad of ["", "   ", "\t"]) {
    const rows = JSON.stringify([{ id: ITEM_A, title: bad }]);
    assertEquals(
      thrownSync(() => parseItems(rows)) !== "",
      true,
      `blank title accepted: ${JSON.stringify(bad)}`,
    );
  }
});

Deno.test("an unknown config key is refused, not stripped", () => {
  // strictObject. Non-strict schemas STRIP unknown keys, so a misspelled
  // `binary` vanished and the provider fell back to PATH -- a typo in a
  // security-sensitive setting silently selecting a different program.
  const msg = thrownSync(() =>
    vault.configSchema.parse({ vaultName: "v", binaray: "/opt/wrong/pass-cli" })
  );
  assertEquals(msg !== "", true, "a misspelled key was accepted");
});

Deno.test("blank config strings are refused", () => {
  for (const bad of ["", "   "]) {
    assertEquals(
      thrownSync(() => vault.configSchema.parse({ vaultName: bad })) !== "",
      true,
      `blank vaultName accepted: ${JSON.stringify(bad)}`,
    );
    assertEquals(
      thrownSync(() =>
        vault.configSchema.parse({ vaultName: "v", binary: bad })
      ) !== "",
      true,
      `blank binary accepted: ${JSON.stringify(bad)}`,
    );
  }
});

Deno.test("a missing field is classified as field-not-found, not item-not-found", () => {
  // The verdict was UNREACHABLE: a generic `does not exist` rule sat above
  // `field does not exist`, so every missing field was reported as a missing
  // item and sent whoever was debugging to look for the wrong thing. Nothing in
  // the suite asserted this verdict at all.
  assertEquals(
    classifyCliFailure("Field does not exist: password", "", 1),
    "field-not-found",
  );
  // The generic rule must still work for its own case.
  assertEquals(
    classifyCliFailure("item does not exist", "", 1),
    "item-not-found",
  );
  // And the vault/item ordering it already had must not regress.
  assertEquals(classifyCliFailure("vault not found", "", 1), "vault-not-found");
});

Deno.test("a flooding CLI is refused on stderr too, not only stdout", async () => {
  // The existing flood test only floods stdout, so the stderr ceiling was
  // deletable without any test noticing.
  const dir = await Deno.makeTempDir();
  const bin = `${dir}/pass-cli-stderr-flood-for-tests`;
  await Deno.writeTextFile(
    bin,
    // 200 KB to stderr (past the 64 KiB ceiling) and VALID JSON on stdout, so
    // the only thing that can refuse this call is the stderr ceiling. The
    // earlier version piped `yes ... 1>&2 | head`, which redirects before the
    // pipe, so head bounded nothing and the test was not exercising the cap.
    "#!/bin/sh\nhead -c 200000 /dev/zero | tr '\\0' 'X' 1>&2\n" +
      `echo '{"password":"${SECRET}"}'\n`,
  );
  await Deno.chmod(bin, 0o755);
  try {
    const p = providerFor(bin);
    const msg = await thrown(() => p.get("Example Service"));
    // Assert the SPECIFIC refusal, not merely that something threw. With the
    // ceiling removed the flood still fails -- at JSON parsing -- so a
    // "did it throw" assertion passes either way and proves nothing. That is
    // exactly the antipattern a mutation audit flagged, and this test had it.
    assertEquals(
      msg.includes("more output than this provider will read"),
      true,
      `expected the overflow refusal, got: ${msg}`,
    );
    assertEquals(msg.includes("EXAMPLE_FLOOD"), false, `LEAKED: ${msg}`);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("an aborted call never invokes pass-cli at all", async () => {
  // Found by an adversarial pass. The abort check sat AFTER child.status, so it
  // stopped the RETURN but not the INVOCATION -- and put() is a write. An
  // aborted put created the item in Proton Pass, put the secret in the process
  // argv table, and then reported "cancelled".
  //
  // The pre-existing cancellation test asserts only on the message and never
  // calls cli.argv(), which is exactly why it stayed green while the CLI was
  // being run. This one asserts the argv log is EMPTY.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    const p = providerFor(cli.path);
    for (
      const call of [
        () => p.get("Example Service", AbortSignal.abort()),
        () => p.list(AbortSignal.abort()),
        () => p.get("Example Service", AbortSignal.abort()),
      ]
    ) {
      const msg = await thrown(call);
      assertEquals(msg.includes("cancelled"), true, `got: ${msg}`);
    }
    const seen = await cli.argv();
    assertEquals(
      seen.length,
      0,
      `pass-cli WAS INVOKED on an aborted call: ${JSON.stringify(seen)}`,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("the fallback guard compares candidate paths by value, not identity", async () => {
  // The guard read `candidates === CANDIDATE_PATHS`, so a structurally
  // identical array defeated it and a non-default bare name resolved to
  // pass-cli's real install location. Rebuild the default list by value and it
  // must still be refused.
  const sameByValue = [
    "/opt/homebrew/bin/pass-cli",
    "/usr/local/bin/pass-cli",
    "/home/linuxbrew/.linuxbrew/bin/pass-cli",
  ];
  const msg = await thrown(() =>
    resolveBinary("pass-cli-value-equality-probe", undefined, sameByValue)
  );
  assertEquals(msg !== "", true, "a value-identical default list was accepted");
  assertEquals(
    msg.includes("must be either the bare name"),
    true,
    `got: ${msg}`,
  );
});

Deno.test("a blank field name is refused", async () => {
  // Blank config strings and blank URI halves were refused; the FIELD half was
  // never checked, so `Item/` and `pass://S/ID/` resolved to a field literally
  // named "" and returned whatever was stored under it.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    const p = providerFor(cli.path);
    for (
      const bad of ["Example Service/", "Example Service/   "]
    ) {
      const r = await getOutcome(p, bad);
      assertEquals(r.value, "", `RETURNED A VALUE for ${bad}`);
      assertEquals(
        r.error.includes("blank field"),
        true,
        `${bad} -> ${r.error}`,
      );
    }
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Round 4 gate blocks. Each of these failed against the code as it stood: the
// suite was fully green with every one of these guards absent, which is how
// ten blocks reached a reviewer twice. Each asserts the DANGEROUS OUTCOME --
// a secret returned, a write misreported, a value handed back from an item
// nobody named -- not merely that an error was raised.
// ---------------------------------------------------------------------------

Deno.test("a title that only RENDERS like the stored one is refused", async () => {
  // Folding was added so two identical-looking items collide and refuse. It
  // also widened the match, and nothing narrowed it again: the stored title
  // here carries a trailing space, the request does not, and get() returned
  // the secret of an item whose title was never the one asked for. Two
  // comments in this repo claimed selection was exact while no code compared.
  const cli = await fakeCli({
    listing: listDoc([listRow({ title: "Example Service " })]),
    stdout: viewDoc(),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(
      r.value,
      "",
      `returned '${r.value}' for a title it never named`,
    );
    assertEquals(r.error.includes("RENDERS the same"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("supplementary-plane variation selectors fold too", async () => {
  // U+E0100 is VS17. The BMP class /[︀-️]/ cannot express it, so two
  // titles differing only by this character folded APART, each matched exactly
  // one item, and the duplicate refusal never fired -- the identical hole the
  // BMP range was added to close, one plane up.
  assertEquals(
    foldTitleForDuplicates("Svc\u{E0100}"),
    foldTitleForDuplicates("Svc"),
    "VS17 must not survive the fold",
  );
  const cli = await fakeCli({
    listing: listDoc([
      listRow({ title: "Svc" }),
      listRow({ id: ITEM_B, title: "Svc\u{E0100}" }),
    ]),
    stdout: viewDoc(),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Svc");
    assertEquals(r.value, "", `returned '${r.value}' from an ambiguous pair`);
    assertEquals(r.error.includes("indistinguishable"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a body describing a DIFFERENT item than the one addressed is refused", async () => {
  // `item view` is invoked with --item-id. The response was then mined for the
  // field without ever checking which item it describes, so a CLI that
  // resolved the wrong one had its value returned as the requested secret.
  const cli = await fakeCli({
    listing: listDoc([listRow()]),
    stdout: viewDoc({ id: ITEM_B }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from the wrong item`);
    assertEquals(
      r.error.includes("a different item id than the one requested"),
      true,
      r.error,
    );
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a body that says it is trashed is refused even when the listing said live", async () => {
  // Liveness was read from the LISTING and never from the response. Those are
  // two separate claims, and a cache or a race can make them disagree -- at
  // which point a deleted credential is still readable, which is the opposite
  // of what deleting it was for.
  const cli = await fakeCli({
    listing: listDoc([listRow()]),
    stdout: viewDoc({ state: "Trashed" }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from a trashed item`);
    assertEquals(r.error.includes("in the trash"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("duplicate field names are ambiguous even when the values AGREE", async () => {
  // `new Set(candidates)` refused only DISTINCT values, so a planted duplicate
  // that simply copied the real one collapsed to a single candidate and the
  // documented refusal never ran. Duplication is the ambiguity; the values are
  // not what makes it one.
  const cli = await fakeCli({
    stdout: viewDoc({
      extra: [
        hiddenField("password", SECRET),
        hiddenField("password", SECRET),
      ],
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from a duplicated field`);
    assertEquals(
      r.error.includes("refusing to choose between them"),
      true,
      r.error,
    );
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a duplicate field name with no value still makes it ambiguous", async () => {
  // The valueless twin never entered the candidate list at all, so it could
  // not even tie: the populated entry won silently. A second entry claiming
  // the name is a second claim on the name.
  const cli = await fakeCli({
    stdout: viewDoc({
      extra: [hiddenField("password", SECRET), { name: "password" }],
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' past a valueless twin`);
    assertEquals(
      r.error.includes("refusing to choose between them"),
      true,
      r.error,
    );
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an object naming the same key twice is refused", async () => {
  // JSON.parse keeps the LAST duplicate and discards the first, before any
  // schema can object. Every strict schema here was therefore validating a
  // document that had already been silently edited.
  const cli = await fakeCli({
    stdout: `{"item":{"password":"${DECOY}","password":"${SECRET}"}}`,
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from a duplicated key`);
    assertEquals(r.error.includes("same key twice"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
    assertEquals(r.error.includes(DECOY), false, "DECOY LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a duplicated state key cannot launder a trashed item into a live one", async () => {
  // The concrete reason the duplicate-key scan exists: last-wins turned
  // {"state":"Trashed","state":"Active"} into an unambiguously live item.
  const cli = await fakeCli({
    listing: listDoc([listRow()]).replace(
      '"state":"Active"',
      '"state":"Trashed","state":"Active"',
    ),
    stdout: viewDoc(),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from a laundered state`);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("output that is not valid UTF-8 is refused, not repaired", async () => {
  // The lossy default decoder rewrote every invalid byte to U+FFFD, so a
  // malformed response could be REPAIRED into well-formed JSON on the way in
  // and then parse cleanly -- altering a title, an id, or the secret itself.
  const cli = await fakeCli({
    stdoutPrintf: '{"item":{"password":"\\377\\376"}}',
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from undecodable bytes`);
    assertEquals(r.error.includes("not valid UTF-8"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("the child receives a named environment, not swamp's whole one", async () => {
  // Both spawns inherited the entire swamp environment, which is shared with
  // every other extension in the run: unrelated API tokens, proxy and TLS
  // overrides, whatever the operator exported. A substituted pass-cli did not
  // need to exfiltrate anything -- it was handed the credentials on arrival.
  const leak = "UNRELATED-TOKEN-MUST-NOT-REACH-THE-CHILD";
  Deno.env.set("SLOG_BOG_UNRELATED_TOKEN", leak);
  const cli = await fakeCli({
    stdout: viewDoc(),
  });
  try {
    await getOutcome(providerFor(cli.path), "Example Service");
    const childEnvText = await cli.env();
    assertEquals(
      childEnvText.includes(leak),
      false,
      "an unrelated credential reached the pass-cli process",
    );
    // ...and the allowlist genuinely passes what the CLI needs, so this is not
    // green merely because the child got nothing at all.
    assertEquals(childEnvText.includes("PATH="), true, "PATH must survive");
  } finally {
    Deno.env.delete("SLOG_BOG_UNRELATED_TOKEN");
    await cli.cleanup();
  }
});

Deno.test("a relative binary path is refused", async () => {
  // `./pass-cli` resolves against whatever directory the swamp process happens
  // to be in, so the same config selected a different executable depending on
  // the caller's cwd -- and a writable working directory became a way to
  // choose the program that receives secret locators and put() values.
  for (const rel of ["./pass-cli", "../pass-cli", "bin/pass-cli"]) {
    const msg = await thrown(() => resolveBinary(rel));
    assertEquals(msg.includes("absolute path"), true, `${rel}: ${msg}`);
  }
  // The sanctioned forms still work: an absolute path is returned as given.
  assertEquals(
    await resolveBinary("/opt/pass/bin/pass-cli"),
    "/opt/pass/bin/pass-cli",
  );
});

// ---------------------------------------------------------------------------
// Round 4 blocks. Three of these four are damage from round 3's own fixes:
// adding validation added surface, exactly as the rule says it does.
// ---------------------------------------------------------------------------

Deno.test("a present-but-non-string id or state does not count as absent", async () => {
  // `typeof x === "string" && ...` made a numeric id or an object state read
  // exactly like an older CLI that omits the field -- so the one shape a
  // confused response would actually take was the shape that skipped the
  // check. Absent is still tolerated; present-and-wrong-typed is not.
  const cases: Array<[string, string]> = [
    ["a numeric id", viewDoc({ itemOverride: { id: 123 } })],
    [
      "an object state",
      viewDoc({ itemOverride: { state: { trashed: true } } }),
    ],
  ];
  for (const [what, body] of cases) {
    const cli = await fakeCli({ stdout: body });
    try {
      const r = await getOutcome(providerFor(cli.path), "Example Service");
      assertEquals(r.value, "", `${what}: returned '${r.value}'`);
      assertEquals(
        r.error.includes("not a string"),
        true,
        `${what}: ${r.error}`,
      );
      assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
    } finally {
      await cli.cleanup();
    }
  }
});

Deno.test("a non-default bare name is refused even when it IS on PATH", async () => {
  // The old guard ran only after the PATH probe had FAILED, so a name that was
  // present and answered `--version` was probed, accepted and returned before
  // the guard could speak -- the check happened on the one path where it no
  // longer mattered. The README documents two accepted forms; this is the code
  // agreeing with it.
  const dir = await Deno.makeTempDir();
  const planted = `${dir}/definitely-not-pass-cli`;
  await Deno.writeTextFile(
    planted,
    '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "1.0"; exit 0; fi\nexit 0\n',
  );
  await Deno.chmod(planted, 0o755);
  const oldPath = Deno.env.get("PATH") ?? "";
  Deno.env.set("PATH", `${dir}:${oldPath}`);
  try {
    const msg = await thrown(() => resolveBinary("definitely-not-pass-cli"));
    assertEquals(
      msg.includes("must be either the bare name"),
      true,
      `a planted executable on PATH was accepted: ${msg}`,
    );
  } finally {
    Deno.env.set("PATH", oldPath);
    await Deno.remove(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Round 5 blocks. Again mostly the previous round's own fixes, reached one
// step further in: a binding that used half an address, an indeterminate-write
// rule that covered one of four post-spawn failures, and an id grammar that
// was an alphabet without a shape.
// ---------------------------------------------------------------------------

Deno.test("an id off the LISTING is held to the same grammar as a URI id", async () => {
  // The URI path validated ids; the title path took whatever the listing said
  // and passed it to --item-id as an arbitrary string. The checked path and
  // the unchecked path disagreed about what an id even is.
  const cli = await fakeCli({
    listing:
      `{"items":[{"id":"ITEM 1/../x","title":"Example Service","state":"Active"}]}`,
    stdout: JSON.stringify({ item: { password: SECRET } }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' via a malformed id`);
    assertEquals(r.error.includes("not a canonical Proton id"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("no error reports a measurement of untrusted output", async () => {
  // `pass-cli returned ${trimmed.length} byte(s) that are not JSON` leaked a
  // measurement of a response that for `item view` is the whole item -- and it
  // was never a byte count, only a UTF-16 code-unit count wearing the label.
  const cli = await fakeCli({ stdout: "this is not json at all, it is prose" });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", "prose was returned as a secret");
    assertEquals(r.error.includes("not JSON"), true, r.error);
    assertEquals(
      /\d+\s*byte/.test(r.error),
      false,
      `error still measures the response: ${r.error}`,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("the LIST parser also reports no measurement of its output", async () => {
  // The same defect in a second place. Fixing only extractValue() left the
  // inventory parser still reporting `${trimmed.length} byte(s)` -- a
  // measurement derived from the secret-store inventory, and still not a byte
  // count.
  const cli = await fakeCli({ listing: "this inventory is not json" });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", "prose was accepted as an inventory");
    assertEquals(r.error.includes("not JSON"), true, r.error);
    assertEquals(
      /\d+\s*byte/.test(r.error),
      false,
      `error still measures the response: ${r.error}`,
    );
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// The real-CLI rewrite. Everything above this line was, until now, written
// against a pass-cli that does not exist.
// ---------------------------------------------------------------------------

Deno.test("an item naming two content types is refused, not picked from", async () => {
  // `content.content` is a tagged union: exactly one key, naming the item type.
  // Two keys means the response does not say what kind of item this is, and
  // choosing a variant is choosing which of two answers to hand back.
  const cli = await fakeCli({
    stdout: viewDoc({
      contentOverride: {
        title: "Example Service",
        note: "",
        item_uuid: "uuid",
        content: { Login: { password: SECRET }, Note: { password: DECOY } },
        extra_fields: [],
      },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from an untyped item`);
    assertEquals(r.error.includes("exactly one item type"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an empty slot is absent, not an empty secret", async () => {
  // Real items carry `"email": ""` for a slot that was never filled in. Handing
  // that back would report success and give the caller an empty credential,
  // which fails later and somewhere else. It is the ordinary "not present"
  // refusal instead.
  const cli = await fakeCli({
    stdout: viewDoc({ login: { password: "", email: "" } }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", "an empty string was returned as a secret");
    assertEquals(r.error.includes("not present"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

// --- round 7: consistency defects in the rewritten reader ---------------

Deno.test("a wrong-typed value slot is malformed, not missing", async () => {
  // Folding a number into "absent" reported a malformed response as a missing
  // field, sending the operator to check their field name when the response
  // was the problem. Same rule the id and state checks already follow.
  const cli = await fakeCli({ stdout: viewDoc({ login: { password: 42 } }) });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}'`);
    assertEquals(r.error.includes("not a string"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an empty CUSTOM field is absent too, not a credential", async () => {
  // The empty-is-absent rule applied to typed slots and not to custom fields,
  // so one rule stated twice disagreed with itself and an empty custom field
  // came back as a successful credential.
  const cli = await fakeCli({
    stdout: viewDoc({ login: {}, extra: [hiddenField("password", "")] }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", "an empty custom field was returned as a secret");
    assertEquals(r.error.includes("not present"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("duplicate listing ids are compared canonically", async () => {
  // Tracking raw spellings let `X` and `X==` pass the duplicate refusal as two
  // rows and then authorise as one, making active-versus-trashed selection
  // depend on listing order.
  const cli = await fakeCli({
    listing: listDoc([
      listRow(),
      listRow({ id: ITEM_A.replace(/=+$/, ""), state: "Trashed" }),
    ]),
    stdout: viewDoc(),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' past a padding variant`);
    assertEquals(r.error.includes("same id"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a TITLE lookup binds the share too, exactly as a URI lookup does", async () => {
  // The row carries its share. Dropping it here meant the two locator forms
  // disagreed about what identity means, and the form most people use was the
  // weaker of the two.
  const cli = await fakeCli({
    listing: listDoc([listRow()]),
    stdout: viewDoc({ shareId: SHARE_B }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from another share`);
    assertEquals(
      r.error.includes("a different share id"),
      true,
      r.error,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a pass:// key is refused, not parsed", async () => {
  // The URI locator is gone. It produced 14 of 39 blocks across six review
  // rounds -- more than any other surface here -- because it carried a second
  // identity scheme that had to be parsed, grammar-checked, canonicalised,
  // bound to a share and liveness-checked separately from the one the listing
  // already provides. What matters now is that a key in the old form FAILS
  // LOUDLY rather than being passed to pass-cli as an opaque title, which is
  // how it would silently address the wrong thing.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    const p = providerFor(cli.path);
    for (
      const key of [
        `pass://${SHARE_A}/${ITEM_A}`,
        `pass://${SHARE_A}/${ITEM_A}/password`,
        "pass://anything",
      ]
    ) {
      const r = await getOutcome(p, key);
      assertEquals(r.value, "", `RETURNED A VALUE for ${key}`);
      assertEquals(r.error.includes("no longer accepts"), true, r.error);
      assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
    }
    // ...and pass-cli was never invoked for any of them.
    assertEquals((await cli.argv()).length, 0, "pass-cli was invoked");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a title containing '/' is not offered, and not guessed at", async () => {
  // `/` is both a legal Proton title character and this provider's field
  // separator, and the escape hatch that used to resolve it -- a pass:// URI
  // -- is gone. This is not hypothetical: real vaults do contain items whose
  // titles carry a slash, which is what made this reachable rather than
  // theoretical. No real title is quoted here -- an item name is a fact about
  // someone's vault, and this file is published.
  //
  // So the collision is refused at both ends. list() must not offer a title it
  // cannot address, and get() must not quietly read field "B" of item "A" when
  // an item genuinely called "A/B" exists. Either guess returns SOME secret
  // with no way for the caller to know which.
  const cli = await fakeCli({
    listing: listDoc([
      listRow({ title: "Plain" }),
      listRow({ id: ITEM_B, title: "A/B" }),
    ]),
    stdout: viewDoc(),
  });
  try {
    const p = providerFor(cli.path);
    assertEquals(
      await p.list(),
      ["Plain"],
      "an unaddressable title was offered by list()",
    );
    const r = await getOutcome(p, "A/B");
    assertEquals(r.value, "", `returned '${r.value}' for an ambiguous key`);
    assertEquals(r.error.includes("is ambiguous"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a slash key is still read as title/field when no such item exists", async () => {
  // The refusal is decided by the VAULT, not by the shape of the key. With no
  // item actually titled "Example Service/apiKey", the ordinary split stands
  // and the custom field resolves -- otherwise every field lookup would have
  // been collateral damage from the fix above.
  const cli = await fakeCli({
    listing: listDoc([listRow()]),
    stdout: viewDoc({ login: {}, extra: [hiddenField("apiKey", SECRET)] }),
  });
  try {
    assertEquals(
      await providerFor(cli.path).get("Example Service/apiKey"),
      SECRET,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an item state is matched exactly, not case-folded", async () => {
  // The README documents a strict two-value enum. `isActiveState` lowercased
  // first, so `aCtIvE` -- a value pass-cli does not emit -- read as LIVE
  // rather than being refused as unrecognised. A response that differs from
  // the documented shape is exactly what the strictness exists to catch.
  const cli = await fakeCli({
    listing: listDoc([listRow({ state: "aCtIvE" })]),
    stdout: viewDoc(),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' on a folded state`);
    assertEquals(r.error.includes("does not recognise"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a relative PATH entry cannot supply the executable", async () => {
  // `PATH=.` produced `./pass-cli` from the resolution walk, which resolves
  // against whatever directory swamp happens to run in -- the same
  // substitution the absolute-path rule refuses at the front door, arriving
  // round the back. What this function returns is absolute or it fails.
  const dir = await Deno.makeTempDir();
  await Deno.writeTextFile(
    `${dir}/pass-cli`,
    '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "1.0"; exit 0; fi\nexit 0\n',
  );
  await Deno.chmod(`${dir}/pass-cli`, 0o755);
  const oldPath = Deno.env.get("PATH") ?? "";
  const oldCwd = Deno.cwd();
  Deno.chdir(dir);
  // The ONLY entry is relative, and it does contain a working pass-cli. If
  // relative entries were honoured this would resolve; it must not.
  Deno.env.set("PATH", ".");
  try {
    // The INVARIANT, not the failure: whatever resolution returns is absolute.
    // With `PATH=.` and a working pass-cli in the current directory, honouring
    // the relative entry returns "./pass-cli"; skipping it either falls
    // through to the standard install prefixes or fails. Both are acceptable.
    // Returning a relative path is not.
    let resolved = "";
    try {
      resolved = await resolveBinary("pass-cli");
    } catch {
      return; // failing to find it at all is a fine outcome here
    }
    assertEquals(
      resolved.startsWith("/"),
      true,
      `resolution returned a relative executable: ${resolved}`,
    );
  } finally {
    Deno.env.set("PATH", oldPath);
    Deno.chdir(oldCwd);
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a malformed listing share id is refused even if the response omits it", async () => {
  // The two halves of the identity rule catch different things. When the
  // RESPONSE carries the field, the response check refuses it. When the
  // response omits it, only the EXPECTATION check is left -- and a listing
  // that gave a malformed share id is a malformed listing whether or not the
  // item view happens to mention one.
  const cli = await fakeCli({
    listing: listDoc([listRow({ shareId: "not a share id!" })]),
    stdout: JSON.stringify({
      item: {
        id: ITEM_A,
        // share_id and vault_id deliberately ABSENT
        content: {
          title: "Example Service",
          note: "",
          item_uuid: "uuid",
          content: { Login: { password: SECRET } },
          extra_fields: [],
        },
        state: "Active",
        flags: [],
        create_time: "2026-01-01T00:00:00Z",
        modify_time: "2026-01-01T00:00:00Z",
      },
      attachments: [],
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' on a malformed listing`);
    assertEquals(
      r.error.includes("listing gave a share id that is not a canonical"),
      true,
      r.error,
    );
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an unreadable share id is not a share id", async () => {
  // `canonicalId` returns undefined for anything malformed, so two DIFFERENT
  // invalid share ids both reduced to undefined and compared equal: the share
  // binding passed precisely when the identity was unreadable. An expectation
  // that cannot be parsed is not an expectation.
  const cli = await fakeCli({
    listing: listDoc([listRow({ shareId: "not a share id!" })]),
    stdout: viewDoc({ shareId: "also not a share id!" }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' on an unreadable share`);
    assertEquals(r.error.includes("canonical Proton id"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an option-looking vault name cannot become an option", async () => {
  // Vault names are operator input and item ids come off the wire; either can
  // begin with `-`. Passed as its own argv entry, pass-cli's option parser is
  // free to read one as a flag. No shell is involved, so no amount of shell
  // avoidance addresses it -- the joined `--option=value` form is what leaves
  // nothing to reinterpret.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    await getOutcome(
      providerFor(cli.path, { vaultName: "--output" }),
      "Example Service",
    );
    const calls = await cli.argv();
    assertEquals(calls.length > 0, true, "pass-cli was never invoked");
    for (const call of calls) {
      // The dangerous outcome: the vault name standing alone as an argument,
      // where it is indistinguishable from a flag the caller meant to pass.
      assertEquals(
        call.includes("--output") &&
          call[call.indexOf("--output") + 1] !== "json",
        false,
        `vault name stood alone as an option: ${call.join(" ")}`,
      );
      assertEquals(
        call.includes("--vault-name=--output"),
        true,
        `vault name not joined to its option: ${call.join(" ")}`,
      );
    }
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a present-but-empty item id is malformed, not missing", async () => {
  // `if (rec.id)` treated "" as absent, so an empty id skipped canonical
  // validation and was written out as `undefined` -- malformed data laundered
  // into "this row simply has no id", which list() then advertises and get()
  // cannot address.
  const cli = await fakeCli({
    listing: listDoc([listRow({ id: "" })]),
    stdout: viewDoc(),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' via an empty id`);
    assertEquals(r.error.includes("canonical Proton id"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an item renamed between listing and viewing is refused", async () => {
  // Resolution reads the LISTING, picks a title, then views the item BY ID --
  // two calls with a gap. Rename the item in the Proton Pass UI inside that
  // gap and the id still resolves, so the secret comes back under a title that
  // no longer names it. `content.title` was parsed and never compared, exactly
  // as `id` and `state` were before it.
  const cli = await fakeCli({
    listing: listDoc([listRow({ title: "Example Service" })]),
    stdout: viewDoc({ title: "Renamed After Listing" }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' after a rename`);
    assertEquals(r.error.includes("titled differently"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a non-string item title in the response is malformed", async () => {
  // Refused by the SCHEMA, not by the binding. `content.title` is
  // `z.string().optional()`, so a non-string title never survives the parse --
  // unlike `id`, `share_id` and `state`, which are `z.unknown()` and therefore
  // need their own type checks. A binding-level check here was unreachable,
  // and the mutation audit reported it UNGUARDED, which is what an unreachable
  // guard looks like from outside. This test keeps the BEHAVIOUR pinned
  // wherever it is enforced.
  const cli = await fakeCli({
    stdout: viewDoc({
      contentOverride: {
        title: 42,
        note: "",
        item_uuid: "uuid",
        content: { Login: { password: SECRET } },
        extra_fields: [],
      },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' on a non-string title`);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a bad config does not quote the model definition into the log", async () => {
  // `ConfigSchema.parse` throws a ZodError whose message quotes the offending
  // input, UNKNOWN KEY NAMES included -- and those come from the caller's
  // model definition. Every other message in this provider is length-bounded
  // and control-escaped first; this one walked past all of it, so a
  // pathological config key could flood or forge run-log lines exactly as a
  // pathological secret key once could.
  const flood = "K".repeat(5000);
  const msg = await thrown(() =>
    Promise.resolve(
      vault.createProvider("proton", {
        vaultName: "v",
        defaultField: "password",
        [flood]: "x",
      } as never),
    )
  );
  assertEquals(msg !== "", true, "an unknown config key was accepted");
  assertEquals(msg.includes(flood), false, "the key name reached the message");
  assertEquals(msg.length < 500, true, `message was ${msg.length} chars`);
});

Deno.test("a custom field lookup validates the item-type block too", async () => {
  // `variantBlock` refuses a response naming zero or several item types. It
  // was called only when the requested field was a VALUE SLOT, so a custom
  // field lookup skipped the structural check and could return a secret out of
  // a document this provider had already refused to recognise. The check is
  // about the response, not about which field was asked for.
  const cli = await fakeCli({
    stdout: viewDoc({
      contentOverride: {
        title: "Example Service",
        note: "",
        item_uuid: "uuid",
        content: { Login: {}, Note: {} },
        extra_fields: [hiddenField("apiKey", SECRET)],
      },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service/apiKey");
    assertEquals(r.value, "", `returned '${r.value}' from an untyped item`);
    assertEquals(r.error.includes("exactly one item type"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("custom field names get the collision rules titles get", async () => {
  // Two fields whose names RENDER identically were two different names here,
  // so each matched one request, the duplicate refusal never fired, and the
  // caller got a confidently wrong value -- the defect the title fold exists
  // to prevent, one level down, unfixed for four rounds while the titles above
  // it were hardened twice.
  const dupes = await fakeCli({
    stdout: viewDoc({
      login: {},
      extra: [
        hiddenField("café", SECRET),
        hiddenField("café", DECOY),
      ],
    }),
  });
  try {
    const r = await getOutcome(
      providerFor(dupes.path),
      "Example Service/café",
    );
    assertEquals(r.value, "", `returned '${r.value}' from lookalike fields`);
    assertEquals(r.error.includes("refusing to choose"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await dupes.cleanup();
  }

  // ...and selection stays EXACT: a field that merely renders the same as the
  // request is refused, not returned. Writing the fold without this is the bug
  // that shipped in the title path and took two rounds to find.
  const lookalike = await fakeCli({
    stdout: viewDoc({ login: {}, extra: [hiddenField("café", SECRET)] }),
  });
  try {
    const r = await getOutcome(
      providerFor(lookalike.path),
      "Example Service/café",
    );
    assertEquals(r.value, "", `returned '${r.value}' for a lookalike name`);
    assertEquals(r.error.includes("renders the same"), true, r.error);
  } finally {
    await lookalike.cleanup();
  }
});

Deno.test("an item from another vault is refused", async () => {
  // `vault_id` was parsed from both the listing and the item body and then
  // discarded by both, so a confused CLI could answer with an item from
  // another vault and nothing would notice.
  const cli = await fakeCli({
    listing: listDoc([listRow()]),
    stdout: viewDoc({ itemOverride: { vault_id: fakeId("OTHERVAULT_") } }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from another vault`);
    assertEquals(
      r.error.includes("a different vault id"),
      true,
      r.error,
    );
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a response naming no item type at all is refused", async () => {
  // `variantBlock` returned undefined when `content.content` was absent and
  // the callers carried on, so a note or a custom field could be read out of a
  // response that never said what kind of item it described. "Structurally
  // incomplete" was already the documented refusal for a body with no content
  // container; a container with no type block is the same claim one level down.
  const cli = await fakeCli({
    stdout: viewDoc({
      contentOverride: {
        title: "Example Service",
        note: "",
        item_uuid: "uuid",
        extra_fields: [hiddenField("apiKey", SECRET)],
      },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service/apiKey");
    assertEquals(r.value, "", `returned '${r.value}' from a typeless item`);
    assertEquals(r.error.includes("no item type at all"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a malformed response id is refused even with nothing to compare it to", async () => {
  // The response id was validated only when the listing supplied an
  // expectation to compare against, so a malformed id in the response passed
  // unexamined whenever the listing had omitted its own. Two different
  // malformed ids canonicalise to undefined and compare EQUAL, which is the
  // binding passing precisely when the identity is unreadable.
  const cli = await fakeCli({
    listing: listDoc([listRow()]),
    stdout: viewDoc({ itemOverride: { vault_id: "not a canonical id!" } }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' on a malformed id`);
    assertEquals(r.error.includes("not a canonical Proton id"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("'session' and 'token' alone do not mean an auth failure", async () => {
  // Both words matched anywhere in any CLI text, so an item genuinely called
  // "Session Token" -- or any field error mentioning either -- was reported as
  // an authentication failure, sending the operator to re-login over a missing
  // field. They are far too common in a password manager's own output to carry
  // a verdict on their own.
  const cli = await fakeCli({
    stderr: "Error: field does not exist: session token",
    exit: 1,
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", "a failing call returned a value");
    assertEquals(
      r.error.includes("session-not-usable"),
      false,
      `a field error was reported as an auth failure: ${r.error}`,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("the id grammar is the one the README documents", () => {
  // The README has said base64url throughout. The code only means it now: it
  // previously accepted impossible lengths, wrong padding amounts, and final
  // characters carrying bits a decoder discards -- three ways for two distinct
  // strings to be the same id, which is what canonicalisation exists to stop.
  //
  // I declined to add length rules twice, on the grounds that Proton ids might
  // be random strings over the alphabet rather than encodings of bytes. That
  // was wrong, and the first attempt failed for a reason worth remembering:
  // it refused `ID1` and took 27 tests down, which was the FIXTURES being
  // unreal rather than the rule being wrong. Every id a real vault returns is
  // 86 base64url characters plus `==`.
  const canonical = fakeId("EXAMPLE_");
  const body = canonical.replace(/=+$/, "");

  // Padded and unpadded spellings of one value normalise together.
  assertEquals(canonicalId(canonical), body);
  assertEquals(canonicalId(body), body);

  // Wrong padding amount for this length.
  assertEquals(canonicalId(body + "="), undefined);
  assertEquals(canonicalId(body + "==="), undefined);
  assertEquals(canonicalId(body + "===="), undefined);

  // A length that cannot encode anything. 86 + 1 is 87, which is `rem 3` and
  // perfectly legal -- 2 bytes in 3 characters. The impossible remainder is 1,
  // so it takes three more characters to reach 89. Asserting the wrong one of
  // these is how a grammar test passes while describing a different grammar.
  assertEquals(canonicalId(body + "AAA"), undefined);

  // Pad bits a decoder would discard. The final character of an 86-character
  // body carries four unused bits, so only alphabet indices that are multiples
  // of 16 are canonical -- `A` is 0, `B` is 1 and is therefore a second
  // spelling of a value that already has one.
  assertEquals(canonicalId(body.slice(0, -1) + "A"), body.slice(0, -1) + "A");
  assertEquals(canonicalId(body.slice(0, -1) + "B"), undefined);

  // `=` anywhere but the end is not padding at all, and characters outside the
  // alphabet are refused however they are arranged.
  assertEquals(canonicalId("IT=EM"), undefined);
  assertEquals(canonicalId("=" + body), undefined);
  assertEquals(canonicalId("ITEM/1"), undefined);
  assertEquals(canonicalId("ITEM%2F"), undefined);
  assertEquals(canonicalId(""), undefined);
  assertEquals(canonicalId("="), undefined);
});

Deno.test("a slow flooding CLI times out as a timeout", async () => {
  // The overflow refusal is rethrown PAST the abort classifier, so nothing
  // downstream can reclassify it: whichever of the two fires first wins
  // permanently. When the deadline the operator set is why the pipe stopped
  // being drained, reporting "pass-cli returned more output than this provider
  // will read" blames the remote for our own stop.
  //
  // WHAT THIS DOES NOT PROVE. The guard that prefers the abort verdict over
  // the overflow refusal cannot be reached on demand: the abort terminates the
  // child, so the flood that would cross the ceiling stops as soon as the
  // condition the guard needs becomes true. This test pins the ordinary
  // behaviour -- a slow CLI that never finishes is a timeout, not a remote
  // overflow -- and the guard itself is marked NOT COVERED in the source.
  const dir = await Deno.makeTempDir();
  const bin = `${dir}/pass-cli`;
  // 8 KB every 200ms crosses the 64 KiB stderr ceiling at roughly 1.6s, so a
  // 1s deadline is reliably already expired when the overflow is raised.
  await Deno.writeTextFile(
    bin,
    "#!/bin/sh\nfor i in 1 2 3 4 5 6 7 8 9 10 11 12; do\n" +
      "  head -c 8000 /dev/zero | tr '\\0' 'X' 1>&2\n  sleep 0.2\ndone\n" +
      "exit 0\n",
  );
  await Deno.chmod(bin, 0o755);
  try {
    const msg = await thrown(() =>
      providerFor(bin, { timeoutSec: 1 }).get("Example Service")
    );
    assertEquals(
      msg.includes("more output than this provider will read"),
      false,
      `a timed-out call was reported as a remote overflow: ${msg}`,
    );
    assertEquals(msg.includes("within 1s"), true, msg);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("an item whose declared type disagrees with its content is refused", async () => {
  // The response states its type twice -- `item_type` and the tag on
  // `content.content` -- and both were parsed and neither compared. Two
  // spellings of one fact that disagree is a response that does not know what
  // it is describing.
  const cli = await fakeCli({
    stdout: viewDoc({
      variant: "Note",
      login: { password: SECRET },
      itemOverride: { item_type: "login" },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from a mistyped item`);
    assertEquals(
      r.error.includes("type disagrees with its"),
      true,
      r.error,
    );
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an item of a different kind than the row it resolved from is refused", async () => {
  // `item_type` was parsed from the listing AND the body and read by neither,
  // so a response describing a different KIND of item than the row it was
  // resolved from went unnoticed. The fifth field to be accepted and ignored
  // here, after state, id, title and vault_id.
  const cli = await fakeCli({
    listing: listDoc([listRow({ extra: { item_type: "login" } })]),
    stdout: viewDoc({
      variant: "Note",
      login: { password: SECRET },
      itemOverride: { item_type: "note" },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from a different kind`);
    assertEquals(r.error.includes("type disagrees with its"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a body omitting item_type is still held to the listed type", async () => {
  // The tag comparison lived inside "the body declared a type", so a body that
  // simply OMITTED `item_type` skipped it -- and an arbitrary single variant
  // could then supply a known field and be returned as the credential while
  // the listing declared another kind. Whichever pair of the three claims is
  // present is the pair that gets checked.
  const cli = await fakeCli({
    listing: listDoc([listRow({ extra: { item_type: "login" } })]),
    stdout: viewDoc({
      variant: "Note",
      login: { password: SECRET },
      // item_type deliberately ABSENT from the body
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' from an untyped body`);
    assertEquals(r.error.includes("type disagrees with its"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a non-string listing item_type fails the parse", async () => {
  // Converting a wrong-typed value into "absent" disables the check that
  // depends on it. That confusion has now appeared four times in this file --
  // `if (rec.id)`, `typeof x === "string" &&`, `|| undefined`, and this -- and
  // every time it turned malformed input into missing input. The schema types
  // the field so the parse refuses it.
  const cli = await fakeCli({
    listing: listDoc([listRow({ extra: { item_type: 7 } })]),
    stdout: viewDoc(),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' on a numeric item_type`);
    assertEquals(r.error.includes("unrecognised shape"), true, r.error);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an Error: on stderr is a failure even when the exit code is 0", async () => {
  // pass-cli reports some failures with exit 0. Only STDOUT was examined, so a
  // process that exited cleanly with an `Error:` on stderr -- and whatever
  // happened to be on stdout, valid or stale -- was read as healthy and mined
  // for a secret.
  const cli = await fakeCli({
    stdout: viewDoc(),
    stderr: "Error: vault not found",
    exit: 0,
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", "a failing call returned a secret");
    assertEquals(r.error.includes("vault-not-found"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a multi-slash key checks every split point, not just the whole key", async () => {
  // The split is taken at the FIRST slash, so `A/B/C` reads as field `B/C` of
  // item `A`. An active item titled `A/B` makes field `C` of `A/B` an equally
  // good reading, and one titled `A/B/C` makes the whole key a title. The
  // guard checked only the last of those, which is worse than not checking:
  // multi-slash keys looked guarded and were not.
  const cli = await fakeCli({
    listing: listDoc([
      listRow({ title: "A" }),
      listRow({ id: ITEM_B, title: "A/B" }),
    ]),
    stdout: viewDoc({ login: {}, extra: [hiddenField("B/C", SECRET)] }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "A/B/C");
    assertEquals(r.value, "", `returned '${r.value}' for an ambiguous key`);
    assertEquals(r.error.includes("is ambiguous"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a multi-slash key still resolves when no split point collides", async () => {
  // The vault decides whether the ambiguity is real, at every split point and
  // not only the last -- so a key with slashes in the FIELD half is untouched
  // when no item is titled with any of its prefixes.
  const cli = await fakeCli({
    listing: listDoc([listRow({ title: "A" })]),
    stdout: viewDoc({
      title: "A",
      login: {},
      extra: [hiddenField("B/C", SECRET)],
    }),
  });
  try {
    assertEquals(await providerFor(cli.path).get("A/B/C"), SECRET);
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a malformed binary is refused at construction, not at first use", async () => {
  // resolveBinary rejects a relative path and an unsanctioned bare name, but
  // it runs on the first LOOKUP -- so a config this provider considers
  // malformed was accepted at construction and complained about later, while
  // the source claimed configuration errors fail at load.
  for (
    const bad of ["./pass-cli", "../pass-cli", "bin/pass-cli", "other-cli"]
  ) {
    const msg = await thrown(() =>
      Promise.resolve(
        vault.createProvider("proton", {
          vaultName: "v",
          defaultField: "password",
          binary: bad,
        } as never),
      )
    );
    assertEquals(msg !== "", true, `'${bad}' was accepted at construction`);
    assertEquals(msg.includes("not valid"), true, msg);
  }
  // ...and the two sanctioned forms still construct.
  for (const good of ["pass-cli", "/opt/pass/bin/pass-cli"]) {
    const msg = await thrown(() =>
      Promise.resolve(
        vault.createProvider("proton", {
          vaultName: "v",
          defaultField: "password",
          binary: good,
        } as never),
      )
    );
    assertEquals(msg, "", `'${good}' was refused: ${msg}`);
  }
});

Deno.test("an unreadable PATH falls back instead of throwing Deno's error", async () => {
  // `Deno.env.get` throws a permission error when --allow-env is narrower than
  // the name asked for, and that error is Deno's: unbounded, unescaped, and
  // raised outside every message discipline in this file. It also aborted
  // resolution entirely, so a perfectly good executable at a standard install
  // prefix was never tried. A PATH we cannot read is an empty PATH.
  const realGet = Deno.env.get;
  // deno-lint-ignore no-explicit-any
  (Deno.env as any).get = (name: string) => {
    if (name === "PATH") {
      throw new Deno.errors.NotCapable("requires env access");
    }
    return realGet.call(Deno.env, name);
  };
  try {
    const msg = await thrown(() => resolveBinary("pass-cli"));
    assertEquals(
      msg.includes("requires env access"),
      false,
      `Deno's permission error reached the caller: ${msg}`,
    );
  } finally {
    // deno-lint-ignore no-explicit-any
    (Deno.env as any).get = realGet;
  }
});

Deno.test("a non-string item_uuid fails the parse", async () => {
  // Typed, not bound, and the difference matters. There is nothing to bind it
  // TO -- a real `item_uuid` is 8 characters where the item id is 88, so it is
  // a different identifier and no expectation the caller supplies constrains
  // it. What it must not do is sit in the schema as `z.unknown()`, where a
  // wrong-typed value is ignored rather than refused.
  const cli = await fakeCli({
    stdout: viewDoc({
      contentOverride: {
        title: "Example Service",
        note: "",
        item_uuid: 12345,
        content: { Login: { password: SECRET } },
        extra_fields: [],
      },
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' on a numeric item_uuid`);
    assertEquals(r.error.includes("does not recognise"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an aborted call is told so even when the config is also bad", async () => {
  // Cancellation-first, tested where it actually bites. Through the provider a
  // malformed `binary` is now refused at construction, so this ordering only
  // shows up on a direct resolveBinary call -- and it is the case that matters:
  // a caller who has already given up should hear that, not a complaint about
  // a `binary` value that was never going to be reached.
  const msg = await thrown(() =>
    resolveBinary("./pass-cli", AbortSignal.abort())
  );
  assertEquals(msg.toLowerCase().includes("cancelled"), true, msg);
  assertEquals(
    msg.includes("absolute path"),
    false,
    `a cancelled call was answered with a configuration complaint: ${msg}`,
  );
});

Deno.test("the README enumerates the methods this provider actually has", () => {
  // gen-readme probes the provider and lists what the object really exposes,
  // so a read-only provider cannot advertise a `put` it lacks. The probe has a
  // fallback for providers whose config it cannot satisfy, and that fallback
  // once shipped: adding construction-time validation of `binary` made the
  // generator's own placeholder config invalid, and the README published
  // "_provider methods could not be determined_" -- documentation that does
  // not document. This asserts the outcome rather than the mechanism.
  const methods = README.slice(README.indexOf("### Methods"));
  assertEquals(
    methods.includes("could not be determined"),
    false,
    "the README shipped the generator's fallback instead of the method list",
  );
  assertEquals(methods.includes("`get(key)`"), true, "get() is not documented");
  assertEquals(methods.includes("`list()`"), true, "list() is not documented");
  // ...and the method this provider does not have is not advertised.
  assertEquals(
    methods.includes("`put(key, value)`"),
    false,
    "the README advertises a put() this provider does not implement",
  );
});

Deno.test("a PASS:// key is refused in any casing", async () => {
  // URI schemes are case-insensitive by RFC 3986, so `PASS://S/I` names the
  // same address `pass://` does -- and it fell through the reserved-prefix
  // check into title/field parsing, where it resolved as field `/S/I` of an
  // item titled `PASS:`. A prefix reserved in only one spelling is not
  // reserved.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    const p = providerFor(cli.path);
    for (const key of ["PASS://x/y", "Pass://x/y", "pAsS://x/y"]) {
      const r = await getOutcome(p, key);
      assertEquals(r.value, "", `RETURNED A VALUE for ${key}`);
      assertEquals(r.error.includes("no longer accepts"), true, r.error);
    }
    assertEquals((await cli.argv()).length, 0, "pass-cli was invoked");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("the separator collision check folds titles like every other one", async () => {
  // Byte equality meant a slash-bearing title differing from the key only by
  // composition, a trailing space or a variation selector slipped past the
  // ambiguity refusal -- and get() then resolved the OTHER reading and handed
  // back a secret from an item nobody named. Detection folds; this is
  // detection.
  const cli = await fakeCli({
    listing: listDoc([
      listRow({ title: "A" }),
      // Renders as "A/B", but carries a trailing space.
      listRow({ id: ITEM_B, title: "A/B " }),
    ]),
    stdout: viewDoc({
      title: "A",
      login: {},
      extra: [hiddenField("B/C", SECRET)],
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "A/B/C");
    assertEquals(r.value, "", `returned '${r.value}' past a folded collision`);
    assertEquals(r.error.includes("is ambiguous"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("environment VALUES are checked, not just their names", async () => {
  // Allowlisting names was half the job. Several of these names are
  // instructions rather than data: the path-valued ones redirect where
  // pass-cli looks for its config and helpers, and DBUS_SESSION_BUS_ADDRESS
  // selects a TRANSPORT -- `unix:` is a local socket, and the same variable
  // accepts `tcp:host=...`, which points the secret store somewhere else with
  // no TLS in sight.
  Deno.env.set("DBUS_SESSION_BUS_ADDRESS", "tcp:host=192.0.2.1,port=1234");
  Deno.env.set("HOME", "relative/not/absolute");
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    await getOutcome(providerFor(cli.path), "Example Service");
    const childEnvText = await cli.env();
    assertEquals(
      childEnvText.includes("tcp:host="),
      false,
      "a non-local D-Bus transport was passed to the child",
    );
    assertEquals(
      childEnvText.includes("HOME=relative/not/absolute"),
      false,
      "a relative HOME was passed to the child",
    );
  } finally {
    Deno.env.delete("DBUS_SESSION_BUS_ADDRESS");
    Deno.env.delete("HOME");
    await cli.cleanup();
  }
});

Deno.test("a D-Bus address with a TCP fallback is not passed on", async () => {
  // A D-Bus address is a SEMICOLON-SEPARATED LIST and a client may use any
  // element, so `startsWith("unix:")` accepted a local socket with a cleartext
  // TCP fallback welded on behind it. Every element must be local or the
  // variable does not travel.
  Deno.env.set(
    "DBUS_SESSION_BUS_ADDRESS",
    "unix:path=/run/ok;tcp:host=192.0.2.1,port=1234",
  );
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    await getOutcome(providerFor(cli.path), "Example Service");
    const childEnvText = await cli.env();
    assertEquals(
      childEnvText.includes("tcp:host="),
      false,
      "a TCP fallback reached the child",
    );
  } finally {
    Deno.env.delete("DBUS_SESSION_BUS_ADDRESS");
    await cli.cleanup();
  }
});

Deno.test("the child's PATH gets the same rule the resolution walk uses", async () => {
  // Resolution skips relative and empty PATH entries and then handed the RAW
  // PATH to the child -- so `.` or an empty component could still select an
  // executable from the working directory, one step further out, if pass-cli
  // invokes a helper. An entry we would not resolve through is not an entry we
  // pass on.
  const realPath = Deno.env.get("PATH") ?? "";
  Deno.env.set("PATH", `.::relative/bin:${realPath}`);
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    await getOutcome(providerFor(cli.path), "Example Service");
    const line = (await cli.env()).split("\n").find((l) =>
      l.startsWith("PATH=")
    ) ?? "";
    const entries = line.slice("PATH=".length).split(":");
    assertEquals(
      entries.every((d) => d.startsWith("/")),
      true,
      `a non-absolute PATH entry reached the child: ${line.slice(0, 120)}`,
    );
  } finally {
    Deno.env.set("PATH", realPath);
    await cli.cleanup();
  }
});

Deno.test("wrong-typed metadata is refused, as the README promises", async () => {
  // `flags`, `create_time` and `modify_time` were `z.unknown()`, which accepts
  // any shape at all -- so "recognised so the parse succeeds" had quietly
  // become "anything goes here" while the README promised the opposite.
  for (
    const bad of [
      { flags: "not-an-array" },
      { create_time: 12345 },
      { modify_time: { when: "now" } },
    ]
  ) {
    const cli = await fakeCli({ stdout: viewDoc({ itemOverride: bad }) });
    try {
      const r = await getOutcome(providerFor(cli.path), "Example Service");
      assertEquals(
        r.value,
        "",
        `returned '${r.value}' with ${JSON.stringify(bad)}`,
      );
      assertEquals(r.error.includes("does not recognise"), true, r.error);
    } finally {
      await cli.cleanup();
    }
  }
});

Deno.test("an id of the wrong length is not a Proton id", () => {
  // Documenting "86 base64url characters plus `==`" while accepting `TQ==`
  // meant malformed identity data crossed the fail-closed boundary wearing a
  // valid-looking shape -- and an id is the thing every binding here compares.
  //
  // This is an OBSERVATION of pass-cli 2.3.2, not a promise Proton has made:
  // a build issuing ids of another length refuses every lookup rather than
  // resolving a wrong one. The trade is stated in the README.
  assertEquals(canonicalId("TQ=="), undefined);
  assertEquals(canonicalId("TQ"), undefined);
  assertEquals(canonicalId("A".repeat(85)), undefined);
  assertEquals(canonicalId("A".repeat(87)), undefined);
  // ...and the observed shape is accepted, padded or not.
  const body = "A".repeat(86);
  assertEquals(canonicalId(body), body);
  assertEquals(canonicalId(`${body}==`), body);
});

Deno.test("a blank or control-bearing item type is not an item type", async () => {
  // "Exactly one key" says how many there are, not that the one NAMES an item
  // type -- so a blank tag, or one carrying a zero-width character, satisfied
  // the count and then had a secret read out of it.
  // NO item_type anywhere -- not on the listing row, not on the body. With one
  // present, the type-agreement check refuses these anyway and this test would
  // pass without the tag rule ever running, which is what the mutation audit
  // reported the first time it was written.
  const rowNoType = () => {
    const r = listRow();
    delete (r as Record<string, unknown>).item_type;
    return r;
  };
  for (const tag of ["", " ", "Log in", "\u200BLogin", "Login "]) {
    const cli = await fakeCli({
      listing: listDoc([rowNoType()]),
      stdout: JSON.stringify({
        item: {
          id: ITEM_A,
          share_id: SHARE_A,
          vault_id: VAULT_A,
          content: {
            title: "Example Service",
            note: "",
            item_uuid: "uuid",
            content: { [tag]: { password: SECRET } },
            extra_fields: [],
          },
          state: "Active",
          flags: [],
          create_time: "2026-01-01T00:00:00Z",
          modify_time: "2026-01-01T00:00:00Z",
        },
        attachments: [],
      }),
    });
    try {
      const r = await getOutcome(providerFor(cli.path), "Example Service");
      assertEquals(
        r.value,
        "",
        `returned '${r.value}' for tag ${JSON.stringify(tag)}`,
      );
      assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
    } finally {
      await cli.cleanup();
    }
  }
});

Deno.test("a null typed slot still claims the name", async () => {
  // `null` is PRESENT-AND-UNSET, not absent. Counting only slots that produced
  // a value meant a null typed `password` alongside a custom field of the same
  // name resolved quietly to the custom field -- two locations claiming one
  // name, which is the ambiguity this function refuses everywhere else.
  const cli = await fakeCli({
    stdout: viewDoc({
      login: { password: null },
      extra: [hiddenField("password", SECRET)],
    }),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' past a null claim`);
    assertEquals(r.error.includes("refusing to choose"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an over-long secret key is refused before any inventory work", async () => {
  // The separator-collision check visits every slash in the key and folds and
  // scans the whole inventory at each one, so key length multiplies inventory
  // size. Keys were already bounded before entering a MESSAGE; this bounds the
  // one that enters the ALGORITHM.
  const cli = await fakeCli({ stdout: viewDoc() });
  try {
    const huge = "a/".repeat(5000);
    const r = await getOutcome(providerFor(cli.path), huge);
    assertEquals(r.value, "", "an unbounded key was processed");
    assertEquals(r.error.includes("too long"), true, r.error);
    // ORDER, observably. A key that is BOTH over-long and control-bearing must
    // report the length: the control-character scan reads the whole string, so
    // if it ran first the bound would be decorating work already done.
    const both = await getOutcome(providerFor(cli.path), `${huge}\u0007`);
    assertEquals(both.error.includes("too long"), true, both.error);
    assertEquals(
      both.error.includes("control character"),
      false,
      `the control-char scan ran before the length bound: ${both.error}`,
    );
    assertEquals((await cli.argv()).length, 0, "pass-cli was invoked anyway");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("an abort mid-lookup cancels rather than returning a secret", async () => {
  // WHAT THIS DOES NOT PROVE. The recheck placed after the awaited command
  // cannot be reached on demand: an abort arriving any earlier is caught by
  // run(), which passes the signal to the child, and every attempt to land it
  // in the gap hit that earlier check instead. This pins the ordinary
  // behaviour -- an abort during a lookup yields a cancellation and never a
  // value -- and the recheck itself is marked NOT COVERED in the source.
  const cli = await fakeCli({ stdout: viewDoc(), delaySec: 1 });
  try {
    const ac = new AbortController();
    const pending = providerFor(cli.path).get("Example Service", ac.signal);
    setTimeout(() => ac.abort(), 60);
    const msg = await pending.then(() => "", (e) => String(e));
    assertEquals(msg.toLowerCase().includes("cancel"), true, msg);
    assertEquals(msg.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a response naming __proto__ is refused", async () => {
  // The one key that defeats "no unrecognised keys" by never being there to
  // recognise: Zod's strict object cannot refuse `__proto__` because the
  // runtime discards it while building the object, so it vanishes before any
  // key-count or catchall check runs. Refused in the TEXT, which is the only
  // place it still exists.
  const cli = await fakeCli({
    stdout: JSON.stringify({
      item: {
        id: ITEM_A,
        share_id: SHARE_A,
        vault_id: VAULT_A,
        content: {
          title: "Example Service",
          note: "",
          item_uuid: "uuid",
          content: { Login: { password: SECRET } },
          extra_fields: [],
        },
        state: "Active",
        flags: [],
        create_time: "2026-01-01T00:00:00Z",
        modify_time: "2026-01-01T00:00:00Z",
      },
      attachments: [],
    }).replace('"attachments":[]', '"attachments":[],"__proto__":{"x":1}'),
  });
  try {
    const r = await getOutcome(providerFor(cli.path), "Example Service");
    assertEquals(r.value, "", `returned '${r.value}' past a __proto__ key`);
    assertEquals(r.error.includes("reserved key"), true, r.error);
    assertEquals(r.error.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a cancellation stays a cancellation, not a lookup failure", async () => {
  // Fixed by STRUCTURE rather than a guard: the abort recheck was moved above
  // the try that wraps every error into "not readable", so a cancellation can
  // no longer reach that catch to be reclassified. This pins the outcome.
  // The catch around the value read wraps every error into "not readable",
  // which turned a caller's own abort into a complaint about the response.
  // CancelledError exists so callers can tell those apart.
  // The abort must land during the ITEM VIEW, which is the call wrapped by the
  // catch under test -- an abort during the earlier LIST propagates from
  // outside it and would pass this test without the rethrow existing.
  const cli = await fakeCli({ stdout: viewDoc(), delaySec: 1 });
  try {
    const ac = new AbortController();
    const pending = providerFor(cli.path).get("Example Service", ac.signal);
    setTimeout(() => ac.abort(), 1300);
    const msg = await pending.then(() => "", (e) => String(e));
    assertEquals(msg.toLowerCase().includes("cancel"), true, msg);
    assertEquals(
      msg.includes("not readable from Proton Pass vault"),
      false,
      `a cancellation was reported as a lookup failure: ${msg}`,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("one provider's PATH resolution cannot select another provider's executable", async () => {
  const first = await fakeCli({});
  const second = await fakeCli({});
  const original = Deno.env.get("PATH");
  try {
    Deno.env.set("PATH", first.path.slice(0, first.path.lastIndexOf("/")));
    assertEquals(await resolveBinary("pass-cli"), first.path);
    Deno.env.set("PATH", second.path.slice(0, second.path.lastIndexOf("/")));
    assertEquals(await resolveBinary("pass-cli"), second.path);
  } finally {
    if (original === undefined) Deno.env.delete("PATH");
    else Deno.env.set("PATH", original);
    await first.cleanup();
    await second.cleanup();
  }
});
