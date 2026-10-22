import type { NodeInfo, Preview } from "./subscription";

const escape = (value: string) => value.replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]!);

export function previewHtml(preview: Preview, params: URLSearchParams): string {
  const nodeRow = (node: NodeInfo, selected = true, filterId?: string) => {
    const unsupported = preview.type === "qx" && !node.qxSupported;
    const reason = unsupported ? "Protocol/options unavailable in QX" : !selected ? `Excluded by include${filterId}` : "";
    return `<li class="node${!selected || unsupported ? " muted" : ""}">
      <span><span class="node-name">${escape(node.name)}</span>${reason ? `<small>${escape(reason)}</small>` : ""}</span>
      <span class="protocol">${escape(node.protocol)}</span></li>`;
  };
  const dumpParams = new URLSearchParams(params);
  dumpParams.set("type", preview.type);
  const dumpPath = `/dump?${dumpParams}`;
  const labels = { "clash": "Mihomo · Global", "clash-geo": "Mihomo · With rules", "qx": "Quantumult X · With rules" };
  const timestamp = preview.updatedAt ? new Date(preview.updatedAt).toUTCString() : "No successful update yet";
  const resourcePath = (id: string) => `/rules/${id}?${new URLSearchParams({ password: params.get("password")!, format: "json" })}`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow,noarchive">
<title>Reef · Subscription preview</title><link rel="stylesheet" href="/preview.css"><script src="/preview.js" defer></script></head>
<body><main>
  <header><a class="brand" href="?${escape(params.toString())}">reef<span class="brand-dot">.</span></a>
    <span class="private-label">Private subscription</span></header>
  <section class="intro"><p class="eyebrow">YOUR CONNECTIONS</p><h1>Choose your route.</h1>
    <p>Filter your relay pools, then use this selection in your client.</p>
    <div class="refresh-bar"><div><p class="snapshot">Last update <time datetime="${escape(preview.updatedAt)}">${escape(timestamp)}</time></p>
      <p class="hint">${preview.cache?.fresh === false ? "No current snapshot. Export is unavailable." : "Refreshes on the first request after one hour."}</p></div>
      <button type="button" id="force-update">Force update</button></div>
    <p id="refresh-status" role="status" aria-live="polite">${escape(preview.cache?.error ?? "")}</p></section>
  <nav class="tabs" aria-label="Preview content"><button type="button" data-tab="nodes" aria-pressed="true">Nodes</button>
    <button type="button" data-tab="rules" aria-pressed="false">Rules</button></nav>
  <form method="get" action="/" id="filters">
    <input type="hidden" name="password" value="${escape(params.get("password")!)}">
    <div class="toolbar"><label for="profile-type">Profile</label><select name="type" id="profile-type">
      ${Object.entries(labels).map(([value, label]) => `<option value="${value}"${value === preview.type ? " selected" : ""}>${label}</option>`).join("")}
    </select><button type="submit">Apply filters</button></div>
    <div data-panel="nodes">
    ${preview.exits.length ? `<section><div class="section-title"><h2>Exit endpoints</h2><span>${preview.exits.length} destinations</span></div>
      <div class="cards">${preview.exits.map(exit => {
        const count = exit.nodes.filter(node => preview.type !== "qx" || node.qxSupported).length;
        return `<article class="card"><h3>${escape(exit.name)}</h3>
        <p class="hint">${count === 0 ? "No compatible endpoint" : count === 1 ? "One protocol · single endpoint" : "Multiple protocols · automatic selection"}</p>
        <ul class="nodes">${exit.nodes.map(node => nodeRow(node)).join("")}</ul></article>`;
      }).join("")}</div></section>` : ""}
    ${preview.pools.length ? `<section><div class="section-title"><h2>Relay pools</h2><span>Also available as direct exits</span></div>
      <div class="cards">${preview.pools.map(pool => {
        const selected = new Set(pool.selected);
        return `<article class="card pool"><div class="pool-heading"><h3>${escape(pool.name)}</h3><span class="count">${selected.size} / ${pool.nodes.length}</span></div>
          <label class="filter-label" for="include${pool.id}">include${pool.id}</label>
          <input id="include${pool.id}" name="include${pool.id}" value="${escape(pool.filter)}" placeholder="All nodes, or comma-separated names" autocomplete="off" spellcheck="false">
          <p class="hint">Match any term in the original node name. Leave empty for all.</p>
          <ul class="nodes pool-nodes">${pool.nodes.map(node => nodeRow(node, selected.has(node.name), pool.id)).join("")}</ul></article>`;
      }).join("")}</div></section>` : ""}
    </div>
  </form>
  ${preview.otherNodes.length ? `<section data-panel="nodes"><h2>Nodes</h2><ul class="nodes card">${preview.otherNodes.map(node => nodeRow(node)).join("")}</ul></section>` : ""}
  <section class="result" data-panel="nodes"><div class="section-title"><h2>Client choices</h2><span>${preview.type === "qx" ? "Reef" : "PROXY"}</span></div>
    <p class="hint">${preview.relays.length
      ? "Use filter mode. Choose an EXIT in Reef, then choose its RELAY pool. Selecting direct in RELAY connects to that exit without an intermediate. Selecting a POOL in Reef uses it as the final exit."
      : "Each relay path uses the selected pool before reaching the exit. Your client tests connectivity."}</p>
    <ul class="choices">${preview.choices.map(choice => `<li>${escape(choice)}</li>`).join("")}</ul>
    ${preview.relays.length ? `<div class="cards">${preview.relays.map(relay => `<article class="card"><h3>${escape(relay.name)}</h3>
      <ul class="choices">${relay.choices.map(choice => `<li>${escape(choice)}</li>`).join("")}</ul></article>`).join("")}</div>
      <p class="hint">Pools and exits with multiple compatible protocols choose nodes automatically. Verify both relay hops in QX network activity; endpoint latency alone does not validate the complete path.</p>` : ""}
    ${preview.errors.length ? `<div class="errors" role="alert"><strong>Export unavailable</strong><ul>${preview.errors.map(error => `<li>${escape(error)}</li>`).join("")}</ul></div>` : ""}
    <div class="actions"><button type="button" id="copy-link" data-path="${escape(dumpPath)}"${preview.errors.length ? " disabled" : ""}>Copy subscription URL</button>
      ${preview.errors.length ? '<span class="disabled">Download configuration</span>' : `<a class="download" href="${escape(dumpPath)}" download="${preview.type === "qx" ? "quantumult-x.conf" : `${preview.type}.yaml`}">Download configuration</a>`}
      <span id="copy-status" role="status" aria-live="polite"></span></div>
    <p class="hint">Anyone with this URL has access to all nodes. Filters select nodes; they do not restrict access.</p>
  </section>
  <section data-panel="rules" hidden><div class="section-title"><h2>Rule order</h2><span>${escape(labels[preview.type])}</span></div>
    <p class="hint">Policies come from the profile template. Pool filters select nodes without changing traffic rules.</p>
    <ol class="rule-order card">${(preview.ruleOrder ?? []).map(rule => `<li>${escape(rule)}</li>`).join("")}</ol>
    <div class="section-title"><h2>Rule resources</h2><span>${preview.resources?.length ?? 0} resources</span></div>
    ${(preview.resources ?? []).map(resource => `<details class="card rule-resource" data-path="${escape(resourcePath(resource.id))}">
      <summary><strong>${escape(resource.name)}</strong><span>${resource.count.toLocaleString("en-US")} rules · ${escape(resource.policy)}${resource.reinject ? " · TUN" : ""}</span></summary>
      <p class="hint">Updated ${escape(timestamp)}</p>
      <form class="rule-search"><input name="q" aria-label="Search ${escape(resource.name)}" placeholder="Search rules" autocomplete="off"><button>Search</button></form>
      <p class="rule-status" role="status" aria-live="polite"></p><ol class="rule-lines"></ol>
      <div class="pagination"><button type="button" data-page="previous" disabled>Previous</button><span class="page-label"></span><button type="button" data-page="next" disabled>Next</button></div>
    </details>`).join("")}
    ${preview.resources?.length ? "" : '<p class="hint">This profile has no remote rule resources in the current snapshot.</p>'}
  </section>
  <footer>Reef · Nodes and rules refresh together. Refresh your client to receive changes.</footer>
</main></body></html>`;
}
