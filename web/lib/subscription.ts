import { createHash, timingSafeEqual } from "node:crypto";
import { stringify } from "yaml";
import { RequestError, validateQuery, selectModel, profileLabels } from "../public/selection.js";
export { RequestError, validateQuery };

export type ProfileType = "clash" | "clash-geo" | "qx";
export type NodeInfo = {
  name: string;
  originalName: string;
  protocol: string;
  qxSupported: boolean;
};
type Pool = { id: string; name: string; group: string; relay?: boolean; nodes: NodeInfo[] };
type Proxy = { name: string; type: string; "dialer-proxy"?: string; [key: string]: unknown };
type Group = { name: string; type: string; proxies: string[]; [key: string]: unknown };
type QxRelay = {
  sections: Record<string, string[]>;
  nodes: { name: string; sourceName: string; line: string; rule: string }[];
  policies: { name: string; kind: string; members: string[]; options: string[] }[];
};
export type RuleResource = {
  id: string; name: string; profile: "clash-geo" | "qx";
  policy: string; reinject: boolean; lines: string[];
};

export type Snapshot = {
  updatedAt: string;
  passwordHash: string;
  exits: { name: string; nodes: NodeInfo[] }[];
  pools: Pool[];
  otherNodes: NodeInfo[];
  proxies: Proxy[];
  sourceNodes?: Proxy[];
  groups: Group[];
  templates: Record<"clash" | "clash-geo", Record<string, unknown>>;
  qx: { body: string | null; error: string | null; choices: string[]; relay: QxRelay | null };
  resources?: RuleResource[];
};

export type Preview = {
  type: ProfileType;
  updatedAt: string;
  exits: Snapshot["exits"];
  otherNodes: NodeInfo[];
  pools: (Pool & { filter: string; matched: string[]; selected: string[] })[];
  choices: string[];
  relays: { name: string; choices: string[] }[];
  errors: string[];
  resources?: (Omit<RuleResource, "lines"> & { count: number })[];
  ruleOrder?: string[];
  cache?: { fresh: boolean; error: string | null };
};

export type Selection = { preview: Preview; proxies: Proxy[]; groups: Group[]; qx: QxRelay | null };

export function authenticate(passwordHash: string, params: URLSearchParams): void {
  const passwords = params.getAll("password");
  if (passwords.length !== 1 || !timingSafeEqual(
    createHash("sha256").update(passwords[0]).digest(),
    Buffer.from(passwordHash, "hex"),
  )) {
    throw new RequestError(404, "Not found");
  }
}

export type SelectionModel = Pick<Snapshot, "updatedAt" | "exits" | "pools" | "otherNodes"> & {
  proxies: Pick<Proxy, "name" | "type" | "dialer-proxy">[];
  groups: Pick<Group, "name" | "type" | "proxies">[];
  qx: { error: string | null; choices: string[]; relay: {
    nodes: Pick<QxRelay["nodes"][number], "name" | "sourceName">[];
    policies: Pick<QxRelay["policies"][number], "name" | "members">[];
  } | null };
  profiles: Record<ProfileType, Pick<Preview, "resources" | "ruleOrder">>;
};

export function selectionModel(snapshot: Snapshot): SelectionModel {
  const node = ({ name, originalName, protocol, qxSupported }: NodeInfo): NodeInfo =>
    ({ name, originalName, protocol, qxSupported });
  return {
    updatedAt: snapshot.updatedAt,
    exits: snapshot.exits.map(exit => ({ name: exit.name, nodes: exit.nodes.map(node) })),
    pools: snapshot.pools.map(pool => ({ id: pool.id, name: pool.name, group: pool.group, relay: pool.relay, nodes: pool.nodes.map(node) })),
    otherNodes: snapshot.otherNodes.map(node),
    proxies: snapshot.proxies.map(proxy => ({ name: proxy.name, type: proxy.type,
      ...(proxy["dialer-proxy"] ? { "dialer-proxy": proxy["dialer-proxy"] } : {}) })),
    groups: snapshot.groups.map(({ name, type, proxies }) => ({ name, type, proxies })),
    qx: { error: snapshot.qx.error, choices: snapshot.qx.choices, relay: snapshot.qx.relay ? {
      nodes: snapshot.qx.relay.nodes.map(({ name, sourceName }) => ({ name, sourceName })),
      policies: snapshot.qx.relay.policies.map(({ name, members }) => ({ name, members })),
    } : null },
    profiles: Object.fromEntries((Object.keys(profileLabels) as ProfileType[]).map(type => [type, {
      resources: (snapshot.resources ?? []).filter(resource => resource.profile === type)
        .map(({ id, name, profile, policy, reinject, lines }) => ({ id, name, profile, policy, reinject, count: lines.length })),
      ruleOrder: previewRules(snapshot, type),
    }])) as SelectionModel["profiles"],
  };
}

export function select(snapshot: Snapshot, params: URLSearchParams): Selection {
  authenticate(snapshot.passwordHash, params);
  const selected = selectModel(selectionModel(snapshot), params);
  const names = new Set(selected.proxies.map(node => node.name));
  const qxNames = new Set(selected.qx?.nodes.map(node => node.name));
  return {
    preview: selected.preview,
    proxies: snapshot.proxies.filter(node => names.has(node.name)),
    groups: snapshot.groups.map((group, index) => ({ ...group, proxies: selected.groups[index].proxies })),
    qx: selected.qx && snapshot.qx.relay ? {
      ...snapshot.qx.relay,
      nodes: snapshot.qx.relay.nodes.filter(node => qxNames.has(node.name)),
      policies: snapshot.qx.relay.policies.map((policy, index) => ({ ...policy, members: selected.qx!.policies[index].members })),
    } : null,
  };
}

export function resourceUrl(origin: string, password: string, id: string): string {
  const url = new URL(`/rules/${id}`, origin);
  url.searchParams.set("password", password);
  return url.href;
}

function previewRules(snapshot: Snapshot, type: ProfileType): string[] {
  const addresses = new Set(snapshot.proxies.map(proxy => proxy.server));
  if (type === "qx") {
    return [
      ...(snapshot.qx.relay ? ["Exit connections → their RELAY selectors", "Pool connections → direct"] : []),
      ...(snapshot.resources ?? []).filter(resource => resource.profile === "qx")
        .map(resource => `RULE-SET,${resource.name},${resource.policy}`),
      ...(snapshot.qx.relay?.sections.filter_local ?? []),
    ];
  }
  return ((snapshot.templates[type].rules ?? []) as string[]).map(rule => {
    const fields = rule.split(",");
    return addresses.has(fields[1]?.replace(/\/(32|128)$/, ""))
      ? `Endpoint connection → ${fields[2]}` : rule;
  });
}

export function dump(snapshot: Snapshot, selection: Selection, location?: { origin: string; password: string }): string {
  if (selection.preview.errors.length) {
    throw new RequestError(422, selection.preview.errors.join("\n"));
  }
  const type = selection.preview.type;
  const rewrite = (line: string) => line.replace(/^reef-resource:([^,\s]+)/, (_, id: string) => {
    if (!location) throw new RequestError(500, "Rule resource origin is unavailable.");
    return resourceUrl(location.origin, location.password, id);
  });
  if (type === "qx") {
    if (selection.qx) {
      const { sections, nodes, policies } = selection.qx;
      const selectedSections = {
        ...sections,
        filter_remote: sections.filter_remote.map(rewrite),
        server_local: nodes.map(node => node.line),
        policy: policies.map(policy => `${policy.kind}=${policy.name}, ${[...policy.members, ...policy.options].join(", ")}`),
        filter_local: [...new Set(nodes.map(node => node.rule)), ...sections.filter_local],
      };
      return Object.entries(selectedSections).map(([name, lines]) => `[${name}]\n${lines.join("\n")}`).join("\n\n") + "\n";
    }
    if (snapshot.qx.body === null) throw new RequestError(422, "Quantumult X export is unavailable.");
    return snapshot.qx.body.split("\n").map(rewrite).join("\n");
  }
  const template = structuredClone(snapshot.templates[type]);
  for (const provider of Object.values((template["rule-providers"] ?? {}) as Record<string, { url: string }>)) {
    provider.url = rewrite(provider.url);
  }
  return stringify({
    ...template, proxies: selection.proxies, "proxy-groups": selection.groups,
  }, {
    lineWidth: 0, aliasDuplicateObjects: false,
    defaultKeyType: "PLAIN", defaultStringType: "QUOTE_DOUBLE",
  });
}
