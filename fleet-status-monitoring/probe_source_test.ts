import { probeScript } from "./probe_source.ts";
Deno.test("packaged Python probe passes macOS startup-data and Linux MemAvailable fixtures", async () => {
  const dir = await Deno.makeTempDir({ prefix: "fleet-probe-fixtures-" });
  try {
    await Deno.writeTextFile(dir + "/probe.py", probeScript);
    await Deno.copyFile(
      new URL("./probe_test.py", import.meta.url),
      dir + "/probe_test.py",
    );
    const r = await new Deno.Command("/usr/bin/python3", {
      args: [dir + "/probe_test.py"],
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (r.code !== 0) throw Error(new TextDecoder().decode(r.stderr));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
