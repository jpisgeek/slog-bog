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
  classifyAbort,
  classifyCliFailure,
  CLI_VERDICTS,
  parseItems,
  vault,
} from "./proton_pass.ts";

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
  },
): Promise<
  {
    path: string;
    argv: () => Promise<string[][]>;
    cleanup: () => Promise<void>;
  }
> {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/pass-cli`;
  // `get` now resolves a title to exactly one LIVE item before viewing it, so
  // the fake has to answer `item list` as well as `item view`. Callers that
  // do not care about resolution get a single active item named to match.
  const listing = opts.listing ??
    `{"items":[{"id":"ID1","title":"${
      opts.title ?? "Example Service"
    }","state":"Active"}]}`;
  const script = [
    "#!/bin/sh",
    // --version probe used by resolveBinary must succeed
    'if [ "$1" = "--version" ]; then echo "fake 1.0"; exit 0; fi',
    // Record argv (tab-separated, one line per invocation).
    `printf '%s\\t' "$@" >> ${dir}/argv; printf '\\n' >> ${dir}/argv`,
    `if [ "$2" = "list" ]; then cat <<'LIST_EOF'\n${listing}\nLIST_EOF\nexit 0; fi`,
    opts.stdout ? `cat <<'STDOUT_EOF'\n${opts.stdout}\nSTDOUT_EOF` : "",
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
  const cli = await fakeCli({ stdout: `{"password":"${SECRET}"}`, exit: 3 });
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
    stdout: `{"password":"${SECRET}"}`,
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
    stdout: JSON.stringify({
      item: {
        fields: [
          { name: "password", content: { Hidden: SECRET } },
          { name: "note", content: { Text: "not the secret" } },
        ],
      },
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
    stdout: JSON.stringify([{ name: "API Key", value: SECRET }]),
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
    stdout: JSON.stringify([{ name: "apiKey", value: SECRET }]),
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
        { id: "1", title: "live", state: "Active" },
        { id: "2", title: "dead", state: "Trashed" },
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
        { id: "1", title: "dup", state: "Active" },
        { id: "2", title: "dup", state: "Active" },
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
      items: [{ id: "1", title: "Example Service", state: "Trashed" }],
    }),
    stdout: `{"password":"${SECRET}"}`,
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
        { id: "1", title: "Example Service", state: "Active" },
        { id: "2", title: "Example Service", state: "Active" },
      ],
    }),
    stdout: `{"password":"${SECRET}"}`,
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

Deno.test("an item with no state field is treated as live", async () => {
  // Older pass-cli builds omit state entirely. Hiding every secret from them
  // would be a worse bug than the one being fixed.
  const cli = await fakeCli({
    listing: JSON.stringify({ items: [{ id: "1", title: "legacy" }] }),
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
  for (const fn of ["get", "put", "list", "getName"]) {
    assertEquals(
      typeof (p as unknown as Record<string, unknown>)[fn],
      "function",
      `missing ${fn}()`,
    );
  }
  assertEquals(p.getName(), "proton");
  assertEquals(vault.type, "@jpisgeek/proton-pass");
});

Deno.test("a pass:// URI naming a trashed item is refused", async () => {
  // This check was written twice and was DEAD both times: locate() returned
  // no id, so `if (id !== undefined)` never ran. It still type-checked,
  // because id destructured as undefined. Hence a test that exercises the
  // path rather than an inspection that reads it.
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [{ id: "ITEM9", title: "whatever", state: "Trashed" }],
    }),
    stdout: `{"password":"${SECRET}"}`,
  });
  try {
    let msg = "";
    try {
      await providerFor(cli.path).get("pass://SHARE1/ITEM9/password");
    } catch (e) {
      msg = String(e);
    }
    assertEquals(
      msg.includes("trashed item"),
      true,
      `expected refusal, got: ${msg}`,
    );
    assertEquals(msg.includes(SECRET), false, "SECRET LEAKED");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a pass:// URI naming a live item still resolves", async () => {
  const cli = await fakeCli({
    listing: JSON.stringify({
      items: [{ id: "ITEM9", title: "whatever", state: "Active" }],
    }),
    stdout: `{"password":"${SECRET}"}`,
  });
  try {
    assertEquals(
      await providerFor(cli.path).get("pass://SHARE1/ITEM9/password"),
      SECRET,
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("a pass:// URI for an item this vault does not list is passed through", async () => {
  // It may address a different vault; refusing there would break a working
  // locator. Documented, and asserted so it stays deliberate.
  const cli = await fakeCli({
    listing: JSON.stringify({ items: [] }),
    stdout: `{"password":"${SECRET}"}`,
  });
  try {
    assertEquals(
      await providerFor(cli.path).get("pass://SHARE1/ELSEWHERE/password"),
      SECRET,
    );
  } finally {
    await cli.cleanup();
  }
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
    stdout: JSON.stringify([{ password: DECOY }]),
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
  const shapes: [string, unknown][] = [
    ["bare field array", [{ name: "password", value: SECRET }]],
    ["wrapped fields", {
      item: { fields: [{ name: "password", content: { Hidden: SECRET } }] },
    }],
    ["top-level property", { password: SECRET }],
    ["login block", { item: { login: { password: SECRET } } }],
  ];
  for (const [what, shape] of shapes) {
    const cli = await fakeCli({ stdout: JSON.stringify(shape) });
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

Deno.test("a text listing must parse EVERY nonblank row", () => {
  // Skipping unparsed rows made a partially-read listing indistinguishable
  // from a complete one -- which is how `get` concludes a key is absent when
  // it is not, and how the duplicate-title check misses the duplicate.
  const good = "- [A1]: Alpha (state=Active)\n- [B2]: Beta (state=Trashed)";
  assertEquals(parseItems(good).length, 2);
  assertEquals(parseItems(good)[1].active, false);
  const partial = `${good}\nWARNING: listing truncated by the server`;
  assertEquals(thrownSync(() => parseItems(partial)) !== "", true);
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
    stdout: `{"password":"${SECRET}"}`,
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
  const cli = await fakeCli({ stdout: `{"password":"${SECRET}"}` });
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
    const view = calls.find((c) => c[1] === "view")!;
    assertEquals(view.includes("--item-id"), true, view.join(" "));
    assertEquals(view[view.indexOf("--item-id") + 1], "ID1");
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// a malformed pass:// URI is refused, not passed through
// ---------------------------------------------------------------------------

Deno.test("a pass:// URI missing a share or item id is refused", async () => {
  const cli = await fakeCli({ stdout: `{"password":"${SECRET}"}` });
  try {
    for (
      const bad of [
        "pass://",
        "pass://SHARE1",
        "pass://SHARE1/",
        "pass:///ITEM9",
      ]
    ) {
      const msg = await thrown(() => providerFor(cli.path).get(bad));
      assertEquals(msg !== "", true, `expected a refusal for ${bad}`);
      assertEquals(msg.includes(SECRET), false, `SECRET LEAKED for ${bad}`);
    }
  } finally {
    await cli.cleanup();
  }
});

// ---------------------------------------------------------------------------
// put(): accept a key, or round-trip it. Never both wrong.
// ---------------------------------------------------------------------------

Deno.test("every key put() accepts is stored under that exact key", async () => {
  // The defect this replaces: put("Item/field") split at the slash and wrote
  // the value to the PASSWORD of an item titled "Item", while get("Item/field")
  // asked for a field named "field". The write reported success and the read
  // could never work. put("pass://S/I") created an item titled "pass:".
  //
  // The property is accept-or-round-trip: for any key put() does not reject,
  // the title it sends to pass-cli must be the key itself.
  const cli = await fakeCli({});
  try {
    const p = providerFor(cli.path);
    let accepted = 0;
    for (
      const key of [
        "Bare Title",
        "Item/field",
        "Item/a/b",
        "pass://SHARE1/ITEM9",
        "pass://SHARE1/ITEM9/password",
      ]
    ) {
      const msg = await thrown(() => p.put(key, SECRET));
      if (msg !== "") {
        assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
        continue; // rejected outright: honest
      }
      accepted++;
      const create = (await cli.argv()).filter((c) => c[1] === "create").pop()!;
      assertEquals(
        create[create.indexOf("--title") + 1],
        key,
        `put('${key}') stored under a different title`,
      );
    }
    assertEquals(accepted, 1, "the bare title must still be accepted");
  } finally {
    await cli.cleanup();
  }
});

Deno.test("put() refuses when defaultField would not read back what it wrote", async () => {
  // put() can only write the password field; get() with no field reads
  // defaultField. Configured apart, a put/get pair silently fails to
  // round-trip -- the same class as the qualified-key defect above.
  const cli = await fakeCli({});
  try {
    const p = providerFor(cli.path, { defaultField: "apiKey" });
    const msg = await thrown(() => p.put("Bare Title", SECRET));
    assertEquals(msg.includes("defaultField"), true, msg);
    assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
    assertEquals((await cli.argv()).length, 0, "nothing should have been sent");
  } finally {
    await cli.cleanup();
  }
});

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
  const p = providerFor("pass-cli-no-such-program-for-tests");
  const msg = await thrown(() => p.get("Example Service", AbortSignal.abort()));
  assertEquals(msg.includes("cancelled"), true, `got: ${msg}`);
  assertEquals(msg.includes("Could not find"), false, `got: ${msg}`);
});

Deno.test("a caller signal reaches the pass-cli process", async () => {
  // Proves the signal is threaded from get()/list()/put() and not merely
  // accepted by run(): with no threading the fake answers happily and the
  // secret comes back.
  const cli = await fakeCli({ stdout: `{"password":"${SECRET}"}` });
  try {
    const p = providerFor(cli.path);
    for (
      const call of [
        () => p.get("Example Service", AbortSignal.abort()),
        () => p.list(AbortSignal.abort()),
        () => p.put("Bare Title", SECRET, AbortSignal.abort()),
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
      items: [{ id: "ID1", title: "other", state: "Active" }],
    }),
    stdout: `{"password":"${SECRET}"}`,
  });
  try {
    const cases: (() => Promise<unknown>)[] = [
      () => providerFor(cli.path).get(huge),
      () => providerFor(cli.path).get(`${huge}/${huge}`),
      () => providerFor(cli.path).get(`pass://${huge}`),
      () => providerFor(cli.path).put(`${huge}/f`, SECRET),
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
      ["put() exposes the value in argv", /visible in the process list/i],
      [
        "absent state means live",
        /`state` field is absent is treated as live/i,
      ],
      [
        "cross-vault URIs are not liveness-checked",
        /passed through untouched/i,
      ],
      ["put() takes bare titles only", /BARE ITEM TITLE only/],
      ["secret keys appear in errors", /Secret keys appear in errors/],
      ["responses are read at named locations", /named\s+locations only/i],
    ] as [string, RegExp][]
  ) {
    assertEquals(re.test(prose), true, `README does not state: ${what}`);
  }
});
