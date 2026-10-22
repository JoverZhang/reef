import { createHash } from "node:crypto";
import { diffArrays } from "diff";
import { selectionModel, type Snapshot } from "./subscription.ts";

export type HistorySummary = { id: string; at: string; trigger: string; added: number; removed: number };
export type HistoryEntry = HistorySummary & { lines: string[] };
export type HistoryOverview = { count: number; latest: HistorySummary | null };
export type HistoryPage = { entries: HistorySummary[]; page: number; pages: number; total: number }
  | { entry: HistorySummary; lines: string[]; page: number; pages: number; total: number };
type Field = { hash: string; value?: string };
export type Baseline = {
  version: 1;
  nodes: Record<string, Record<string, Field>>;
  collections: Record<string, string[]>;
  rules: Record<string, string[]>;
  resolution: Record<string, Record<string, Field>>;
};

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
}
const visibleFields = new Set(["name", "type", "server", "port", "network", "udp", "tls", "flow", "skip-cert-verify",
  "client-fingerprint", "packet-encoding", "dialer-proxy", "sni", "servername", "alpn", "cipher", "address"]);
const displayValue = (key: string, value?: string) => visibleFields.has(key) ? value ?? "[not recorded]" : "***";

export function displayHistoryLines(lines: string[]): string[] {
  return lines.map(line => line.replace(/^([+-] )(.+): \[(?:previous|updated) value hidden\]$/,
    (_, sign: string, key: string) => `${sign}${key}: ${displayValue(key)}`));
}
function fields(node: Record<string, unknown>, prefix = ""): Record<string, Field> {
  return Object.fromEntries(Object.entries(node).flatMap(([key, value]): [string, Field][] => {
    const path = prefix + key;
    if (value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length) {
      return Object.entries(fields(value as Record<string, unknown>, path + "."));
    }
    const encoded = canonical(value);
    return [[path, { hash: createHash("sha256").update(encoded).digest("hex"),
      ...(visibleFields.has(path) ? { value: encoded } : {}) }]];
  }));
}
const normalized = (lines: string[]) => lines.map(line => line.trim())
  .filter(line => line && !line.startsWith("#") && !line.startsWith("//"))
  .map(line => line.split(",").map(part => part.trim()).join(","));

export function comparisonBaseline(snapshot: Snapshot): Baseline {
  const model = selectionModel(snapshot);
  const rules: Record<string, string[]> = {};
  for (const [type, profile] of Object.entries(model.profiles)) rules[`Profile rules / ${type}`] = normalized(profile.ruleOrder ?? []);
  for (const resource of snapshot.resources ?? []) {
    rules[`Rules / ${resource.id}`] = [`policy: ${resource.policy}`, `reinject: ${resource.reinject}`, ...normalized(resource.lines)];
  }
  if (!snapshot.exits.length) for (const group of snapshot.groups) {
    rules[`Group / ${group.name}`] = [`type: ${group.type}`, ...(group.type === "url-test" ? [...group.proxies].sort() : group.proxies)];
  }
  return {
    version: 1,
    nodes: Object.fromEntries((snapshot.sourceNodes ?? snapshot.proxies).map(node => [node.name, fields(node)])),
    collections: Object.fromEntries([
      ...snapshot.exits.map(exit => [`Exit / ${exit.name}`, exit.nodes.map(node => node.name).sort()]),
      ...snapshot.pools.map(pool => [`Pool ${pool.id} / ${pool.name}`, pool.nodes.map(node => node.name).sort()]),
    ]),
    rules,
    resolution: Object.fromEntries((snapshot.qx.relay?.nodes ?? []).map(node =>
      [node.sourceName, fields({ address: node.rule })])),
  };
}

function changedLines(before: string[], after: string[]): string[] {
  if (before.length === after.length && before.every((line, index) => line === after[index])) return [];
  // Bound work for large rule replacements. The fallback still includes the complete change.
  const parts = diffArrays(before, after, { timeout: 300, maxEditLength: 4000 }) ??
    [{ removed: true, added: false, value: before }, { added: true, removed: false, value: after }];
  return parts.flatMap((part, index) => {
    if (part.added || part.removed) return part.value.map(line => (part.added ? "+ " : "- ") + line);
    const lines = part.value.map(line => "  " + line);
    if (index === 0) return lines.slice(-2);
    if (index === parts.length - 1) return lines.slice(0, 2);
    return lines.length <= 4 ? lines : [...lines.slice(0, 2), "  ...", ...lines.slice(-2)];
  });
}
const names = (before: object, after: object) => [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
const label = (value: string) => value.replace(/[\r\n]/g, " ");

export function compare(before: Baseline | null, after: Baseline): string[] {
  if (!before || before.version !== after.version) return [];
  const result: string[] = [];
  const append = (title: string, lines: string[]) => {
    if (!lines.some(line => /^[+-] /.test(line))) return;
    if (result.length) result.push("");
    result.push(`@@ ${label(title)} @@`);
    for (const line of lines) result.push(line);
  };
  for (const category of ["nodes", "resolution"] as const) {
    for (const name of names(before[category], after[category])) {
      const oldFields = before[category][name] ?? {}, newFields = after[category][name] ?? {};
      const lines: string[] = [];
      for (const key of names(oldFields, newFields)) {
        const oldField = oldFields[key], newField = newFields[key];
        if (oldField?.hash === newField?.hash) continue;
        if (oldField) lines.push(`- ${label(key)}: ${displayValue(key, oldField.value)}`);
        if (newField) lines.push(`+ ${label(key)}: ${displayValue(key, newField.value)}`);
      }
      append(`${category === "nodes" ? "Node" : "QX resolution"} / ${name}`, lines);
    }
  }
  for (const category of ["collections", "rules"] as const) {
    for (const name of names(before[category], after[category])) {
      append(name, changedLines(before[category][name] ?? [], after[category][name] ?? []));
    }
  }
  return result;
}

export function changeSummary(id: string, at: string, trigger: string, lines: string[]): HistorySummary {
  return { id, at, trigger, added: lines.filter(line => line.startsWith("+ ")).length,
    removed: lines.filter(line => line.startsWith("- ")).length };
}
