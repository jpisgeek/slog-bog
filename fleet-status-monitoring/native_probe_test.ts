import {
  linuxVersion,
  macVersion,
  observeHost,
  type ProbeProvider,
} from "./native_probe.ts";
const check = (ok: unknown) => {
  if (!ok) throw Error("Assertion failed");
};
function fixture(platform = "darwin") {
  const paths: string[] = [];
  const p: ProbeProvider = {
    platform: () => platform,
    architecture: () => "aarch64",
    release: () => "example-kernel",
    cores: () => 8,
    uptime: () => 123,
    load: () => 1,
    memory: () => ({ total: 16 * 1024 ** 3, available: 8 * 1024 ** 3 }),
    text: async (path) => {
      paths.push(path);
      return platform === "darwin"
        ? "<plist><dict><key>ProductVersion</key><string>99.1</string></dict></plist>"
        : 'NAME="Example Linux"\nVERSION_ID="1.2"\n';
    },
    directory: async (path) => {
      paths.push(path);
      return true;
    },
    capacity: async (path) => {
      paths.push(path);
      return { total: 500 * 1024 ** 3, available: 100 * 1024 ** 3 };
    },
    now: () => Date.parse("2026-11-09T12:00:00.000Z"),
  };
  return { p, paths };
}
Deno.test("native macOS observation reads ProductVersion and startup Data capacity, without enumerating mounts", async () => {
  const { p, paths } = fixture();
  const s = await observeHost(p);
  check(
    s.osVersion === "99.1" && s.family === "macos" &&
      s.diskAvailableBytes === 100 * 1024 ** 3,
  );
  check(
    JSON.stringify(paths) === JSON.stringify([
      "/System/Library/CoreServices/SystemVersion.plist",
      "/System/Volumes/Data",
      "/System/Volumes/Data",
    ]),
  );
});
Deno.test("native Linux observation reads literal os-release fields and root capacity", async () => {
  const { p, paths } = fixture("linux");
  const s = await observeHost(p);
  check(
    s.osName === "Example Linux" && s.osVersion === "1.2" &&
      paths.includes("/"),
  );
});
Deno.test("malformed OS metadata produces an unknown version rather than a kernel-as-product-version substitution", async () => {
  const { p } = fixture();
  p.text = async () => "<key>ProductVersion</key><string>&external;</string>";
  const s = await observeHost(p);
  check(s.osVersion === null && s.kernel === "example-kernel");
});
Deno.test("unsupported Windows load and capacity stay null, never fabricated idle or full-disk values", async () => {
  const { p, paths } = fixture("windows");
  p.load = () => {
    throw Error("Must not measure unsupported load");
  };
  const s = await observeHost(p);
  check(
    s.family === "windows" && s.osVersion === null &&
      s.kernel === "example-kernel" && s.load1 === null &&
      s.diskAvailableBytes === null && paths.length === 0,
  );
});
Deno.test("failed native capacity observation does not scan alternative volumes or images", async () => {
  const { p, paths } = fixture();
  p.capacity = async (path) => {
    paths.push(path);
    throw Error();
  };
  const s = await observeHost(p);
  check(
    s.diskTotalBytes === null &&
      paths.filter((x) => x === "/System/Volumes/Data").length === 2,
  );
});
Deno.test("OS metadata parsers do not evaluate shell or XML content", () => {
  check(
    macVersion("<key>ProductVersion</key><string>$(command)</string>") === null,
  );
  check(linuxVersion('VERSION_ID="$(command)"').version === null);
});
