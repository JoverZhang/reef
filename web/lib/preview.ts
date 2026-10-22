import type { Preview, SelectionModel } from "./subscription.ts";
import type { HistoryOverview } from "./history.ts";
import { escape, inventoryHtml, choicesHtml, rulesHtml, statusHtml } from "../public/view.js";

export type PreviewData = {
  model: SelectionModel | null;
  cache: { fresh: boolean; error: string | null };
  history: HistoryOverview;
};

export function previewHtml(preview: Preview, params: URLSearchParams, data: PreviewData): string {
  // Escaping '<' prevents a node name from closing this inert JSON script element.
  const embedded = JSON.stringify(data).replace(/</g, "\\u003c");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow,noarchive">
<title>Reef · Subscription preview</title><link rel="stylesheet" href="/preview.css"><script type="module" src="/preview.js"></script></head>
<body><main>
  <header><a class="brand" href="?${escape(params.toString())}">reef<span class="brand-dot">.</span></a><span class="private-label">Private subscription</span></header>
  <section class="intro"><p class="eyebrow">YOUR CONNECTIONS</p><h1>Choose your route.</h1>
    <p>Filter your relay pools, then use this selection in your client.</p>
    <div class="refresh-bar"><div id="snapshot-status">${statusHtml(preview.updatedAt, data.cache, data.history)}</div>
      <div class="buttons"><button type="button" id="force-update">Force update</button><button type="button" id="open-history" class="secondary">History <span id="history-count">${data.history.count}</span></button></div></div>
    <p id="refresh-status" role="status" aria-live="polite">${escape(data.cache.error ?? "")}</p></section>
  <form method="get" action="/" id="filters"><input type="hidden" name="password" value="${escape(params.get("password")!)}">
    <div id="inventory">${inventoryHtml(preview)}</div>
    <section class="result" id="client-choices">${choicesHtml(preview, params)}</section>
    <noscript><button type="submit">Apply selection</button></noscript>
  </form>
  <section id="rules">${rulesHtml(preview, params.get("password")!)}</section>
  <footer>Reef · Nodes and rules refresh together. Refresh your client to receive changes.</footer>
</main>
<dialog id="history-dialog" aria-labelledby="history-title"><div class="section-title"><h2 id="history-title">Update history</h2><button type="button" id="close-history" class="secondary" autofocus>Close</button></div>
  <p class="hint">Last 50 changes · + added / - removed · sensitive values hidden</p>
  <p id="history-status" class="hint" role="status" aria-live="polite"></p><div id="history-list"></div><button id="history-more" class="secondary" hidden>Load older changes</button></dialog>
<script id="preview-data" type="application/json">${embedded}</script>
</body></html>`;
}
