import { statfs } from "node:fs/promises";
import { Sample } from "./schema.ts";

/** Narrow provider seam for fixture-tested OS observation; no network or process API. */
export interface ProbeProvider {
  platform(): string;
  architecture(): string;
  release(): string;
  cores(): number;
  uptime(): number;
  load(): number;
  memory(): { total: number; available: number };
  text(path: string): Promise<string>;
  directory(path: string): Promise<boolean>;
  capacity(path: string): Promise<{ total: number; available: number }>;
  now(): number;
}
async function smallText(path: string): Promise<string> {
  const file = await Deno.open(path, { read: true });
  try {
    const info = await file.stat();
    if (info.size > 65536) throw Error("OS metadata too large");
    const bytes = new Uint8Array(65537);
    let used = 0;
    while (used < bytes.length) {
      const n = await file.read(bytes.subarray(used));
      if (n === null) break;
      used += n;
    }
    if (used > 65536) throw Error("OS metadata too large");
    return new TextDecoder().decode(bytes.subarray(0, used));
  } finally {
    file.close();
  }
}
/** Native implementation reads only system metadata and the startup data filesystem. */
export const nativeProvider: ProbeProvider = {
  platform: () => Deno.build.os,
  architecture: () => Deno.build.arch,
  release: () => Deno.osRelease(),
  cores: () => navigator.hardwareConcurrency,
  uptime: () => Deno.osUptime(),
  load: () => Deno.loadavg()[0],
  memory: () => Deno.systemMemoryInfo(),
  text: smallText,
  directory: async (path) => {
    try {
      const s = await Deno.lstat(path);
      return s.isDirectory && !s.isSymlink;
    } catch {
      return false;
    }
  },
  capacity: async (path) => {
    const s = await statfs(path);
    return {
      total: s.blocks * s.bsize,
      available: Math.max(0, s.bavail) * s.bsize,
    };
  },
  now: () => Date.now(),
};
/** Parse only the literal ProductVersion field; no XML entities or code are evaluated. */
export function macVersion(text: string): string | null {
  const value = /<key>ProductVersion<\/key>\s*<string>([^<]{1,80})<\/string>/
    .exec(text)?.[1];
  return value && /^\d+(?:\.\d+){1,3}$/.test(value) ? value : null;
}
/** Read literal distribution fields without sourcing or executing os-release. */
export function linuxVersion(
  text: string,
): { name: string; version: string | null } {
  const fields = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const m = /^(NAME|VERSION_ID)=(.{0,200})$/.exec(line);
    if (!m) continue;
    let value = m[2];
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) value = value.slice(1, -1);
    fields.set(m[1], value);
  }
  const name = fields.get("NAME");
  const version = fields.get("VERSION_ID");
  return {
    name:
      name && name.length <= 160 && ![...name].some((c) => c.charCodeAt(0) < 32)
        ? name
        : "Linux",
    version: version && /^[A-Za-z0-9._+-]{1,80}$/.test(version)
      ? version
      : null,
  };
}
/** Observe one local system, retaining null for unavailable metrics. */
export async function observeHost(provider: ProbeProvider = nativeProvider) {
  const platform = provider.platform();
  const family = platform === "darwin"
    ? "macos"
    : platform === "linux"
    ? "linux"
    : platform === "windows"
    ? "windows"
    : "other";
  let osName = family === "macos"
    ? "macOS"
    : family === "windows"
    ? "Windows NT"
    : family === "linux"
    ? "Linux"
    : "Other";
  let osVersion: string | null = null;
  const kernel = provider.release();
  try {
    if (family === "macos") {
      osVersion = macVersion(
        await provider.text("/System/Library/CoreServices/SystemVersion.plist"),
      );
    } else if (family === "linux") {
      const d = linuxVersion(await provider.text("/etc/os-release"));
      osName = d.name;
      osVersion = d.version;
    }
  } catch { /* Version remains explicitly unavailable. */ }
  let memoryTotalBytes: number | null = null,
    memoryAvailableBytes: number | null = null;
  try {
    const m = provider.memory();
    memoryTotalBytes = m.total;
    memoryAvailableBytes = m.available;
  } catch { /* Unsupported measurement. */ }
  let diskTotalBytes: number | null = null,
    diskAvailableBytes: number | null = null;
  if (family === "macos" || family === "linux") {
    const path =
      family === "macos" && await provider.directory("/System/Volumes/Data")
        ? "/System/Volumes/Data"
        : "/";
    try {
      const d = await provider.capacity(path);
      diskTotalBytes = d.total;
      diskAvailableBytes = d.available;
    } catch { /* No alternative mount scan or image fallback. */ }
  }
  let load1: number | null = null;
  try {
    if (family === "macos" || family === "linux") load1 = provider.load();
  } catch { /* Unsupported measurement. */ }
  let uptimeSeconds: number | null = null;
  try {
    uptimeSeconds = provider.uptime();
  } catch { /* Unsupported measurement. */ }
  return Sample.parse({
    schemaVersion: 1,
    observedAt: new Date(provider.now()).toISOString(),
    family,
    osName,
    osVersion,
    kernel,
    architecture: provider.architecture(),
    logicalCores: provider.cores(),
    uptimeSeconds,
    memoryTotalBytes,
    memoryAvailableBytes,
    memoryAvailableKind: "OS available-memory estimate",
    diskTotalBytes,
    diskAvailableBytes,
    load1,
  });
}
