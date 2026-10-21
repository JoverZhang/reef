import { createHash, timingSafeEqual } from "node:crypto";
import { stringify } from "yaml";

export type ProfileType = "clash" | "clash-geo" | "qx";
export type NodeInfo = {
  name: string;
  originalName: string;
  protocol: string;
  qxSupported: boolean;
};
type Pool = { id: string; name: string; group: string; nodes: NodeInfo[] };
type Proxy = { name: string; type: string; "dialer-proxy"?: string; [key: string]: unknown };
type Group = { name: string; type: string; proxies: string[]; [key: string]: unknown };

export type Snapshot = {
  updatedAt: string;
  passwordHash: string;
  exits: { name: string; nodes: NodeInfo[] }[];
  pools: Pool[];
  otherNodes: NodeInfo[];
  proxies: Proxy[];
  groups: Group[];
  templates: Record<"clash" | "clash-geo", Record<string, unknown>>;
  qx: { body: string | null; error: string | null; choices: string[] };
};

export class RequestError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export type Preview = {
  type: ProfileType;
  updatedAt: string;
  exits: Snapshot["exits"];
  otherNodes: NodeInfo[];
  pools: (Pool & { filter: string; selected: string[] })[];
  choices: string[];
  errors: string[];
};

export type Selection = { preview: Preview; proxies: Proxy[]; groups: Group[] };

export function select(snapshot: Snapshot, params: URLSearchParams): Selection {
  // Authenticate before validating filters or revealing the available pool IDs.
  const passwords = params.getAll("password");
  if (passwords.length !== 1 || !timingSafeEqual(
    createHash("sha256").update(passwords[0]).digest(),
    Buffer.from(snapshot.passwordHash, "hex"),
  )) {
    throw new RequestError(404, "Not found");
  }
  const allowed = new Set(["password", "type", ...snapshot.pools.map(pool => `include${pool.id}`)]);
  for (const key of params.keys()) {
    if (!allowed.has(key)) throw new RequestError(400, "Unknown query parameter or pool ID.");
    if (params.getAll(key).length !== 1) throw new RequestError(400, "Query parameters must not be repeated.");
  }
  const type = params.get("type") ?? "clash-geo";
  if (type !== "clash" && type !== "clash-geo" && type !== "qx") {
    throw new RequestError(400, "type must be clash, clash-geo, or qx.");
  }
  const errors: string[] = [];
  const pools = snapshot.pools.map(pool => {
    const filter = (params.get(`include${pool.id}`) ?? "").trim();
    const terms = filter.split(",").map(term => term.trim().toLowerCase()).filter(Boolean);
    if (filter && !terms.length) throw new RequestError(400, "Include filters must contain a search term.");
    const selected = pool.nodes.filter(node => !terms.length || terms.some(term =>
      node.originalName.toLowerCase().includes(term),
    )).map(node => node.name);
    if (!selected.length) errors.push(`include${pool.id} selects no nodes in ${pool.name}.`);
    return { ...pool, filter, selected };
  });
  const poolNodes = new Set(pools.flatMap(pool => pool.nodes.map(node => node.name)));
  const selectedNodes = new Set(pools.flatMap(pool => pool.selected));
  const proxies = snapshot.proxies.filter(node => !poolNodes.has(node.name) || selectedNodes.has(node.name));
  const poolGroups = new Map(pools.map(pool => [pool.group, pool.selected]));
  const groups = snapshot.groups.map(group => ({
    ...group, proxies: poolGroups.get(group.name) ?? [...group.proxies],
  }));
  const known = new Set(["DIRECT", "REJECT", ...proxies.map(node => node.name), ...groups.map(group => group.name)]);
  if (groups.some(group => group.proxies.some(name => !known.has(name))) ||
      proxies.some(node => node["dialer-proxy"] && !known.has(node["dialer-proxy"]))) {
    errors.push("Filtering removes a node required by another path. Adjust the pool filters.");
  }
  if (type === "qx" && snapshot.qx.error) errors.push(snapshot.qx.error);
  return {
    proxies, groups,
    preview: {
      type, updatedAt: snapshot.updatedAt, exits: snapshot.exits, otherNodes: snapshot.otherNodes,
      pools, choices: type === "qx" && snapshot.qx.body !== null
        ? snapshot.qx.choices : groups.find(group => group.name === "PROXY")?.proxies ?? [], errors,
    },
  };
}

export function dump(snapshot: Snapshot, selection: Selection): string {
  if (selection.preview.errors.length) {
    throw new RequestError(422, selection.preview.errors.join("\n"));
  }
  const type = selection.preview.type;
  if (type === "qx") {
    if (snapshot.qx.body === null) throw new RequestError(422, "Quantumult X export is unavailable.");
    return snapshot.qx.body;
  }
  return stringify({
    ...snapshot.templates[type], proxies: selection.proxies, "proxy-groups": selection.groups,
  }, {
    lineWidth: 0, aliasDuplicateObjects: false,
    defaultKeyType: "PLAIN", defaultStringType: "QUOTE_DOUBLE",
  });
}
