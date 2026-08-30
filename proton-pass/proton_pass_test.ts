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
import { classifyCliFailure, vault } from "./proton_pass.ts";

const SECRET = "SUPER-SECRET-VALUE-must-never-be-logged";

/** Write an executable fake pass-cli emitting the given stdout/stderr/exit. */
async function fakeCli(
  opts: {
    stdout?: string;
    stderr?: string;
    exit?: number;
    listing?: string;
    title?: string;
  },
): Promise<{ path: string; cleanup: () => Promise<void> }> {
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
    `if [ "$2" = "list" ]; then cat <<'LIST_EOF'\n${listing}\nLIST_EOF\nexit 0; fi`,
    opts.stdout ? `cat <<'STDOUT_EOF'\n${opts.stdout}\nSTDOUT_EOF` : "",
    opts.stderr ? `cat >&2 <<'STDERR_EOF'\n${opts.stderr}\nSTDERR_EOF` : "",
    `exit ${opts.exit ?? 0}`,
  ].join("\n");
  await Deno.writeTextFile(path, script);
  await Deno.chmod(path, 0o755);
  return {
    path,
    cleanup: () => Deno.remove(dir, { recursive: true }),
  };
}

const providerFor = (binary: string) =>
  vault.createProvider("proton", {
    vaultName: "myvault",
    defaultField: "password",
    binary,
  });

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
