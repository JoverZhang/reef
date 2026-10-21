import fs from "node:fs";
import vm from "node:vm";

// The official ESM build targets browsers. Supply that environment without
// process/require, network APIs, or access to Reef's files and environment.
const context = vm.createContext({
  console: Object.fromEntries(
    ["log", "info", "warn", "error", "debug"].map((name) => [name, () => {}]),
  ),
});

try {
  const module = new vm.SourceTextModule(fs.readFileSync(process.argv[2], "utf8"), { context });
  await module.link(() => { throw new Error("Unexpected dependency"); });
  await module.evaluate({ timeout: 10000 });
  const input = fs.readFileSync(0, "utf8");
  const proxies = module.namespace.parse(input);
  if (proxies.length !== JSON.parse(input).proxies.length) {
    throw new Error("Parser dropped nodes");
  }
  for (const proxy of proxies) {
    proxy["skip-cert-verify"] ??= false;
    // QX ignores pins when tls-verification=false; Mihomo still enforces them.
    if (proxy["tls-fingerprint"] || proxy["tls-pubkey-sha256"]) {
      proxy["skip-cert-verify"] = false;
    }
    if (proxy["tls-fingerprint"]) {
      proxy["tls-fingerprint"] = proxy["tls-fingerprint"].replaceAll(":", "");
    }
  }
  const output = module.namespace.produce(proxies, "QX");
  const lines = output.split("\n").filter(Boolean).map((line) => {
    const options = line.split(",");
    // QX's VLESS TLS and WSS use obfs-host for SNI. The input validator
    // ensures any WebSocket Host matches SNI before these are combined.
    if (line.startsWith("vless=")) {
      const hasHost = options.some((part) => part.startsWith("obfs-host="));
      return options.flatMap((part) => {
        if (!part.startsWith("tls-host=")) return [part];
        return hasHost ? [] : [part.replace(/^tls-host=/, "obfs-host=")];
      }).join(", ");
    }
    return options.join(", ");
  });
  process.stdout.write(JSON.stringify(lines));
} catch {
  // Never forward a parser exception, node, or conversion log to CI.
  process.exitCode = 1;
}
