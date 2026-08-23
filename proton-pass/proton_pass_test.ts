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
import { vault } from "./proton_pass.ts";

const SECRET = "SUPER-SECRET-VALUE-must-never-be-logged";

/** Write an executable fake pass-cli emitting the given stdout/stderr/exit. */
async function fakeCli(
  opts: { stdout?: string; stderr?: string; exit?: number },
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/pass-cli`;
  const script = [
    "#!/bin/sh",
    // --version probe used by resolveBinary must succeed
    'if [ "$1" = "--version" ]; then echo "fake 1.0"; exit 0; fi',
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
    assertEquals(
      msg.includes("item not found"),
      true,
      "the actionable Error: line should still surface",
    );
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
    assertEquals(
      msg.includes("stdout withheld"),
      true,
      "the error should say stdout was withheld rather than print it",
    );
  } finally {
    await cli.cleanup();
  }
});

Deno.test("stderr is surfaced (it carries no item contents)", async () => {
  const cli = await fakeCli({
    stdout: `{"password":"${SECRET}"}`,
    stderr: "could not reach the Proton API",
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
    assertEquals(msg.includes("could not reach the Proton API"), true);
    assertEquals(msg.includes(SECRET), false, `SECRET LEAKED: ${msg}`);
  } finally {
    await cli.cleanup();
  }
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
    stdout: JSON.stringify([{ title: "Item A" }, { title: "Item B" }]),
  });
  try {
    const p = providerFor(cli.path);
    assertEquals(await p.list(), ["Item A", "Item B"]);
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
