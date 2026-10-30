import { profileLabels } from "./selection.js";

export const escape = value => String(value).replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]);
export const timestamp = value => value ? new Date(value).toUTCString() : "No successful update yet";

function nodeRow(node, type, selected = true, filterId) {
  const unsupported = type === "qx" && !node.qxSupported;
  const reason = unsupported ? "Protocol/options unavailable in QX" : !selected ? `Excluded by include${filterId}` : "";
  return `<li class="node${!selected || unsupported ? " muted" : ""}"><span><span class="node-name">${escape(node.name)}</span>
    ${reason ? `<small>${escape(reason)}</small>` : ""}</span><span class="protocol">${escape(node.protocol)}</span></li>`;
}

export function poolNodesHtml(pool, type) {
  const selected = new Set(pool.selected), matched = new Set(pool.matched);
  const ordered = [...pool.nodes.filter(node => matched.has(node.name)), ...pool.nodes.filter(node => !matched.has(node.name))];
  return ordered.map(node => nodeRow(node, type, selected.has(node.name), pool.id)).join("");
}

export function inventoryHtml(preview) {
  return `${preview.exits.length ? `<section><div class="section-title"><h2>Exit endpoints</h2><span>${preview.exits.length} destinations</span></div>
    <div class="cards">${preview.exits.map(exit => {
      const count = exit.nodes.filter(node => preview.type !== "qx" || node.qxSupported).length;
      return `<article class="card"><h3>${escape(exit.name)}</h3><p class="hint">${count === 0 ? "No compatible endpoint" : count === 1 ? "One protocol · single endpoint" : "Multiple protocols · automatic selection"}</p>
        <ul class="nodes">${exit.nodes.map(node => nodeRow(node, preview.type)).join("")}</ul></article>`;
    }).join("")}</div></section>` : ""}
    ${preview.pools.length ? `<section><div class="section-title"><h2>Pools</h2><span>Available as final exits</span></div>
      <div class="cards">${preview.pools.map(pool => `<article class="card pool" data-pool="${escape(pool.id)}">
        <p class="hint">${pool.relay === false ? "Exit only" : "Relay and exit"}</p>
        <div class="pool-heading"><h3>${escape(pool.name)}</h3><span class="count">${pool.selected.length} / ${pool.nodes.length}</span></div>
        <label class="filter-label" for="include${pool.id}">Include names</label>
        <input id="include${pool.id}" name="include${pool.id}" value="${escape(pool.filter)}" placeholder="All nodes, or comma-separated names" autocomplete="off" spellcheck="false">
        <p class="hint">Match part of a name. Commas mean OR. Matches move first.</p>
        <ul class="nodes pool-nodes">${poolNodesHtml(pool, preview.type)}</ul></article>`).join("")}</div></section>` : ""}
    ${preview.otherNodes.length ? `<section><h2>Nodes</h2><ul class="nodes card">${preview.otherNodes.map(node => nodeRow(node, preview.type)).join("")}</ul></section>` : ""}`;
}

export function choicesHtml(preview, params) {
  const query = new URLSearchParams(params); query.set("type", preview.type);
  const path = `/dump?${query}`;
  return `<div class="section-title"><h2>Client choices</h2><div class="profile-picker"><label for="profile-type">Profile</label>
    <select name="type" id="profile-type">${Object.entries(profileLabels).map(([value, label]) => `<option value="${value}"${value === preview.type ? " selected" : ""}>${label}</option>`).join("")}</select></div></div>
    <p class="hint">${preview.relays.length ? "Use filter mode. Choose an EXIT in Reef, then choose its RELAY pool. Selecting direct in RELAY connects to that exit without an intermediate. Selecting a POOL in Reef uses it as the final exit."
      : "Each relay path uses the selected pool before reaching the exit. Your client tests connectivity."}</p>
    <ul class="choices">${preview.choices.map(choice => `<li>${escape(choice)}</li>`).join("")}</ul>
    ${preview.relays.length ? `<div class="cards">${preview.relays.map(relay => `<article class="card"><h3>${escape(relay.name)}</h3>
      <ul class="choices">${relay.choices.map(choice => `<li>${escape(choice)}</li>`).join("")}</ul></article>`).join("")}</div>
      <p class="hint">In each POOL, select a node manually or select AUTO for automatic selection. Manual selections stay pinned. Exits with multiple compatible protocols choose automatically. Verify both relay hops in QX network activity; endpoint latency alone does not validate the complete path.</p>` : ""}
    <div id="selection-errors" class="errors" role="alert"${preview.errors.length ? "" : " hidden"}><strong>Export unavailable</strong><ul>${preview.errors.map(error => `<li>${escape(error)}</li>`).join("")}</ul></div>
    <div class="actions"><button type="button" id="copy-link" data-path="${escape(path)}"${preview.errors.length ? " disabled" : ""}>Copy subscription URL</button>
      <a id="download" class="download"${preview.errors.length ? ' aria-disabled="true"' : ` href="${escape(path)}"`} download="${preview.type === "qx" ? "quantumult-x.conf" : `${preview.type}.yaml`}">Download configuration</a>
      <span id="copy-status" role="status" aria-live="polite"></span></div>
    <p class="hint">Anyone with this URL has access to all nodes. Filters select nodes; they do not restrict access.</p>`;
}

export function rulesHtml(preview, password) {
  const query = new URLSearchParams({ password, format: "json" });
  return `<div class="section-title"><h2>Rules</h2><span>${profileLabels[preview.type]}</span></div>
    <p class="hint">Policies come from the profile template. Pool filters select nodes without changing traffic rules.</p>
    <ol class="rule-order card">${(preview.ruleOrder ?? []).map(rule => `<li>${escape(rule)}</li>`).join("")}</ol>
    <div class="section-title"><h2>Rule resources</h2><span>${preview.resources?.length ?? 0} resources</span></div>
    ${(preview.resources ?? []).map(resource => `<details class="card rule-resource" data-id="${escape(resource.id)}" data-path="${escape(`/rules/${resource.id}?${query}`)}">
      <summary><strong>${escape(resource.name)}</strong><span>${resource.count.toLocaleString("en-US")} rules · ${escape(resource.policy)}${resource.reinject ? " · TUN" : ""}</span></summary>
      <p class="hint">Updated ${escape(timestamp(preview.updatedAt))}</p>
      <form class="rule-search"><input name="q" aria-label="Search ${escape(resource.name)}" placeholder="Search rules" autocomplete="off"><button>Search</button></form>
      <p class="rule-status" role="status" aria-live="polite"></p><ol class="rule-lines"></ol>
      <div class="pagination"><button type="button" data-page="previous" disabled>Previous</button><span class="page-label"></span><button type="button" data-page="next" disabled>Next</button></div>
    </details>`).join("")}
    ${preview.resources?.length ? "" : '<p class="hint">This profile has no remote rule resources in the current snapshot.</p>'}`;
}

export function statusHtml(updatedAt, cache, history) {
  return `<div><p class="hint">Last checked</p><strong>${escape(timestamp(updatedAt))}</strong>
      <p class="hint">${!cache.fresh ? "No current snapshot. Export is unavailable." : !history.latest ? "Baseline initialized. No changes recorded." : history.latest.at === updatedAt ? "Content changed." : "No changes."}</p></div>
    <div><p class="hint">Last changed</p><strong>${history.latest ? escape(timestamp(history.latest.at)) : "No changes recorded"}</strong>
      <p class="hint">${history.latest ? `+${history.latest.added} -${history.latest.removed} lines` : "Only updates with differences enter history."}</p></div>`;
}
