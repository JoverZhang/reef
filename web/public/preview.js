import { selectModel } from "./selection.js";
import { escape, timestamp, inventoryHtml, poolNodesHtml, choicesHtml, rulesHtml, statusHtml } from "./view.js";

const $ = id => document.getElementById(id);
const params = new URLSearchParams(location.search);
const password = params.get("password");
let data = JSON.parse($("preview-data").textContent);
let rulesVersion = "", historyPage = 0, historyEpoch = 0, historyLoading = false;
const ruleViews = new Map();

function updateURL() {
  const url = new URL(location.href); url.search = params.toString();
  history.replaceState(null, "", url);
}
function updateStatus() {
  $("snapshot-status").innerHTML = statusHtml(data.model?.updatedAt ?? "", data.cache, data.history);
  $("history-count").textContent = data.history.count;
}
function render(inventory = false) {
  updateStatus();
  if (!data.model) return;
  const active = document.activeElement, focusId = active?.id;
  const range = active instanceof HTMLInputElement ? [active.selectionStart, active.selectionEnd] : null;
  const scroll = window.scrollY;
  let preview;
  try { preview = selectModel(data.model, params).preview; }
  catch (error) {
    $("selection-errors").hidden = false;
    $("selection-errors").textContent = error.message;
    $("copy-link").disabled = true;
    $("download").removeAttribute("href");
    $("download").setAttribute("aria-disabled", "true");
    updateURL(); return;
  }
  if (!data.cache.fresh) preview.errors.push(data.cache.error ?? "A current snapshot is unavailable.");
  if (inventory) $("inventory").innerHTML = inventoryHtml(preview);
  else for (const pool of preview.pools) {
    const card = document.querySelector(`[data-pool="${pool.id}"]`);
    card.querySelector(".count").textContent = `${pool.selected.length} / ${pool.nodes.length}`;
    card.querySelector(".pool-nodes").innerHTML = poolNodesHtml(pool, preview.type);
  }
  $("client-choices").innerHTML = choicesHtml(preview, params);
  const version = `${preview.type}:${preview.updatedAt}`;
  if (version !== rulesVersion) {
    $("rules").innerHTML = rulesHtml(preview, password);
    bindRules(); rulesVersion = version;
  }
  if (focusId && $(focusId)) {
    $(focusId).focus({ preventScroll: true });
    if (range && $(focusId) instanceof HTMLInputElement) $(focusId).setSelectionRange(...range);
  }
  window.scrollTo({ top: scroll, behavior: "instant" });
  updateURL();
}

async function jsonResponse(response) {
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}
function bindRules() {
  document.querySelectorAll(".rule-resource").forEach(resource => {
    const view = ruleViews.get(resource.dataset.id) ?? { page: 1, query: "", open: false };
    ruleViews.set(resource.dataset.id, view);
    let pending = false, loaded = false;
    const search = resource.querySelector("form"), status = resource.querySelector(".rule-status");
    const previous = resource.querySelector('[data-page="previous"]'), next = resource.querySelector('[data-page="next"]');
    search.elements.q.value = view.query;
    async function load() {
      if (pending) return;
      pending = true; search.querySelector("button").disabled = previous.disabled = next.disabled = true;
      status.textContent = "Loading rules…";
      try {
        const url = new URL(resource.dataset.path, location.origin);
        url.searchParams.set("page", view.page); url.searchParams.set("q", view.query);
        const result = await jsonResponse(await fetch(url, { cache: "no-store" }));
        if (result.page > result.pages) { view.page = result.pages; pending = false; return load(); }
        const lines = resource.querySelector(".rule-lines");
        lines.replaceChildren(...result.lines.map(line => {
          const item = document.createElement("li"); item.textContent = line; return item;
        }));
        lines.start = (result.page - 1) * 100 + 1;
        resource.querySelector(".page-label").textContent = `Page ${result.page} / ${result.pages}`;
        status.textContent = `${result.total.toLocaleString()} matching rules`;
        previous.disabled = result.page <= 1; next.disabled = result.page >= result.pages; loaded = true;
      } catch (error) { status.textContent = error.message || "Rules could not be loaded."; }
      finally { pending = false; search.querySelector("button").disabled = false; }
    }
    resource.addEventListener("toggle", () => { view.open = resource.open; if (resource.open && !loaded) load(); });
    search.addEventListener("submit", event => {
      event.preventDefault(); if (pending) return;
      view.query = search.elements.q.value; view.page = 1; load();
    });
    previous.addEventListener("click", () => { view.page--; load(); });
    next.addEventListener("click", () => { view.page++; load(); });
    resource.open = view.open;
  });
}

$("filters").addEventListener("submit", event => { event.preventDefault(); render(); });
function filterInput(event) {
  if (!event.target.name?.startsWith("include") || event.isComposing) return;
  params.set(event.target.name, event.target.value); render();
  event.target.closest(".pool").querySelector(".pool-nodes").scrollTop = 0;
}
$("inventory").addEventListener("input", filterInput);
$("inventory").addEventListener("compositionend", filterInput);
$("client-choices").addEventListener("change", event => {
  if (event.target.id === "profile-type") { params.set("type", event.target.value); render(true); }
});
$("client-choices").addEventListener("click", async event => {
  if (event.target.id !== "copy-link") return;
  try {
    await navigator.clipboard.writeText(new URL(event.target.dataset.path, location.origin).href);
    $("copy-status").textContent = "Subscription URL copied.";
  } catch { $("copy-status").textContent = "Copy the link from Download configuration."; }
});
$("force-update").addEventListener("click", async () => {
  $("force-update").disabled = true;
  $("refresh-status").textContent = "Updating nodes and rules… This may take a minute.";
  try {
    const response = await fetch("/refresh", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }), cache: "no-store",
    });
    if (!response.headers.get("content-type")?.includes("application/json")) throw new Error(await response.text());
    const result = await response.json();
    data = result; rulesVersion = ""; render(true);
    historyEpoch++; historyPage = 0; historyLoading = false; $("history-list").replaceChildren();
    if ($("history-dialog").open) loadHistory();
    if (!response.ok) throw new Error(result.error || "Update failed. Retry shortly.");
    $("refresh-status").textContent = result.history.latest?.at === result.updatedAt ? "Updated. View the diff in History." : "Checked successfully. No changes.";
  } catch (error) {
    if (data.model && Date.now() - Date.parse(data.model.updatedAt) >= 3_600_000) { data.cache.fresh = false; render(); }
    $("refresh-status").textContent = error.message || "Update failed. Retry shortly.";
  } finally { $("force-update").disabled = false; }
});

async function fetchHistory(page, id) {
  const query = new URLSearchParams({ password, page: String(page) }); if (id) query.set("id", id);
  return jsonResponse(await fetch(`/history?${query}`, { cache: "no-store" }));
}
function historyEntry(entry) {
  const details = document.createElement("details"); details.className = "history-entry";
  details.innerHTML = `<summary><span class="history-meta">${escape(timestamp(entry.at))} · ${escape(entry.trigger)}</span><strong>+${entry.added} -${entry.removed} lines</strong></summary>
    <p class="hint diff-status" role="status"></p><pre class="diff-code" hidden><code></code></pre><button class="secondary diff-more" hidden>Show more lines</button>`;
  let page = 0, pending = false;
  const status = details.querySelector(".diff-status"), more = details.querySelector(".diff-more"), code = details.querySelector("code");
  async function load() {
    if (pending) return;
    pending = true; more.disabled = true; status.textContent = "Loading diff…";
    try {
      const result = await fetchHistory(page + 1, entry.id); page = result.page;
      for (const line of result.lines) {
        const span = document.createElement("span");
        span.className = line.startsWith("+ ") ? "added" : line.startsWith("- ") ? "removed" : line.startsWith("@@") ? "diff-hunk" : "";
        span.textContent = line + "\n"; code.append(span);
      }
      details.querySelector("pre").hidden = false; more.hidden = page >= result.pages;
      status.textContent = result.pages > 1 ? `${Math.min(page * 200, result.total)} / ${result.total} lines` : "";
    } catch (error) { status.textContent = error.message || "History could not be loaded."; }
    finally { pending = false; more.disabled = false; }
  }
  details.addEventListener("toggle", () => { if (details.open && !page) load(); });
  more.addEventListener("click", load); return details;
}
async function loadHistory() {
  if (historyLoading) return;
  historyLoading = true; $("history-more").disabled = true;
  const epoch = historyEpoch;
  $("history-status").textContent = "Loading history…";
  try {
    const result = await fetchHistory(historyPage + 1);
    if (epoch !== historyEpoch) return;
    historyPage = result.page;
    for (const entry of result.entries) $("history-list").append(historyEntry(entry));
    $("history-more").hidden = historyPage >= result.pages;
    $("history-status").textContent = result.total ? `${result.total} changes retained. Unchanged and failed updates do not use a slot.` : "No changes recorded yet. Unchanged updates do not enter history.";
    if (historyPage === 1 && $("history-list").firstElementChild) $("history-list").firstElementChild.open = true;
  } catch (error) { if (epoch === historyEpoch) $("history-status").textContent = error.message || "History could not be loaded."; }
  finally { if (epoch === historyEpoch) { historyLoading = false; $("history-more").disabled = false; } }
}
$("open-history").addEventListener("click", () => {
  $("history-dialog").showModal(); if (!historyPage) loadHistory();
});
$("close-history").addEventListener("click", () => $("history-dialog").close());
$("history-more").addEventListener("click", loadHistory);
render();
