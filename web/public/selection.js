// This module runs in both the browser and the subscription server. It accepts
// only the safe graph produced by selectionModel; it never fetches or authenticates.
export const profileLabels = { clash: "Mihomo · Global", "clash-geo": "Mihomo · With rules", qx: "Quantumult X · With rules" };

export class RequestError extends Error {
  /** @param {number} status @param {string} message */
  constructor(status, message) { super(message); this.status = status; }
}

/** @param {URLSearchParams} params @param {string[]} poolIds @returns {import("../lib/subscription.ts").ProfileType} */
export function validateQuery(params, poolIds) {
  const allowed = new Set(["password", "type", ...poolIds.map(id => `include${id}`)]);
  for (const key of params.keys()) {
    if (!allowed.has(key)) throw new RequestError(400, "Unknown query parameter or pool ID.");
    if (params.getAll(key).length !== 1) throw new RequestError(400, "Query parameters must not be repeated.");
  }
  const type = params.get("type") ?? "clash-geo";
  if (type !== "clash" && type !== "clash-geo" && type !== "qx") {
    throw new RequestError(400, "type must be clash, clash-geo, or qx.");
  }
  return type;
}

/** @param {import("../lib/subscription.ts").SelectionModel} snapshot @param {URLSearchParams} params */
export function selectModel(snapshot, params) {
  const type = validateQuery(params, snapshot.pools.map(pool => pool.id));
  /** @type {string[]} */
  const errors = [];
  const pools = snapshot.pools.map(pool => {
    const filter = (params.get(`include${pool.id}`) ?? "").trim();
    const terms = filter.split(",").map(term => term.trim().toLowerCase()).filter(Boolean);
    if (filter && !terms.length) throw new RequestError(400, "Include filters must contain a search term.");
    const matched = pool.nodes.filter(node => !terms.length || terms.some(term =>
      node.originalName.toLowerCase().includes(term),
    ));
    const selected = matched.filter(node => type !== "qx" || node.qxSupported).map(node => node.name);
    if (!matched.length) errors.push(`include${pool.id} selects no nodes in ${pool.name}.`);
    else if (!selected.length) errors.push(`include${pool.id} selects no QX-compatible nodes in ${pool.name}.`);
    return { ...pool, filter, matched: matched.map(node => node.name), selected };
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
  const qx = type === "qx" && snapshot.qx.relay ? {
    ...snapshot.qx.relay,
    nodes: snapshot.qx.relay.nodes.filter(node => !poolNodes.has(node.sourceName) || selectedNodes.has(node.sourceName)),
    policies: snapshot.qx.relay.policies.map(policy => ({
      ...policy, members: poolGroups.get(policy.name) ?? [...policy.members],
    })),
  } : null;
  if (qx) {
    const known = new Set(["direct", "reject", ...qx.nodes.map(node => node.name), ...qx.policies.map(policy => policy.name)]);
    if (qx.policies.some(policy => !policy.members.length || policy.members.some(name => !known.has(name)))) {
      errors.push("QX filtering leaves an empty or unresolved policy. Adjust the pool filters.");
    }
  }
  return {
    proxies, groups, qx,
    preview: {
      type, updatedAt: snapshot.updatedAt, exits: snapshot.exits, otherNodes: snapshot.otherNodes,
      pools, choices: type === "qx" ? snapshot.qx.choices : groups.find(group => group.name === "PROXY")?.proxies ?? [],
      relays: qx?.policies.filter(policy => policy.name.startsWith("RELAY | "))
        .map(policy => ({ name: policy.name, choices: policy.members })) ?? [],
      errors,
      resources: snapshot.profiles[type].resources,
      ruleOrder: snapshot.profiles[type].ruleOrder,
    },
  };
}
