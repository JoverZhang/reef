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
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow,noarchive">
<title>Reef · Subscription preview</title><link rel="stylesheet" href="/preview.css"><script src="/preview.js" defer></script></head>
<body><main>
  <header><a class="brand" href="?${escape(params.toString())}">reef<span class="brand-dot">.</span></a>
    <span class="private-label">Private subscription</span></header>
  <section class="intro"><p class="eyebrow">YOUR CONNECTIONS</p><h1>Choose your route.</h1>
    <p>Filter your relay pools, then use this selection in your client.</p>
    <p class="snapshot">Snapshot <time datetime="${escape(preview.updatedAt)}">${escape(new Date(preview.updatedAt).toUTCString())}</time></p></section>
  <form method="get" action="/" id="filters">
    <input type="hidden" name="password" value="${escape(params.get("password")!)}">
    <div class="toolbar"><label for="profile-type">Profile</label><select name="type" id="profile-type">
      ${Object.entries(labels).map(([value, label]) => `<option value="${value}"${value === preview.type ? " selected" : ""}>${label}</option>`).join("")}
    </select><button type="submit">Apply filters</button></div>
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
  </form>
  ${preview.otherNodes.length ? `<section><h2>Nodes</h2><ul class="nodes card">${preview.otherNodes.map(node => nodeRow(node)).join("")}</ul></section>` : ""}
  <section class="result"><div class="section-title"><h2>Client choices</h2><span>${preview.type === "qx" ? "Reef" : "PROXY"}</span></div>
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
  <footer>Reef · Updates when you publish a new snapshot.</footer>
</main></body></html>`;
}
