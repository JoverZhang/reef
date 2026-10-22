const form = document.getElementById("filters");
const copy = document.getElementById("copy-link");
const status = document.getElementById("copy-status");

document.getElementById("profile-type").addEventListener("change", () => form.requestSubmit());
form.addEventListener("input", () => {
  copy.disabled = true;
  const download = document.querySelector("a.download");
  if (download) {
    download.removeAttribute("href");
    download.setAttribute("aria-disabled", "true");
  }
  status.textContent = "Apply filters to update the preview and link.";
});
copy.addEventListener("click", async () => {
  const url = new URL(copy.dataset.path, window.location.href).href;
  try {
    await navigator.clipboard.writeText(url);
    status.textContent = "Subscription URL copied.";
  } catch {
    status.textContent = "Copy the link from Download configuration.";
  }
});

const tabs = document.querySelectorAll("[data-tab]");
function showTab() {
  const selected = location.hash === "#rules" ? "rules" : "nodes";
  tabs.forEach(tab => tab.setAttribute("aria-pressed", String(tab.dataset.tab === selected)));
  document.querySelectorAll("[data-panel]").forEach(panel => { panel.hidden = panel.dataset.panel !== selected; });
  form.action = selected === "rules" ? "/#rules" : "/";
}
tabs.forEach(tab => tab.addEventListener("click", () => { location.hash = tab.dataset.tab; }));
window.addEventListener("hashchange", showTab);
showTab();

const refresh = document.getElementById("force-update");
const refreshStatus = document.getElementById("refresh-status");
refresh.addEventListener("click", async () => {
  refresh.disabled = true;
  refreshStatus.textContent = "Updating nodes and rules… This may take a minute.";
  try {
    const response = await fetch("/refresh", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: form.elements.password.value }), cache: "no-store",
    });
    if (!response.ok) throw new Error(await response.text());
    location.reload();
  } catch (error) {
    refreshStatus.textContent = error.message || "Update failed. Retry shortly.";
    refresh.disabled = false;
  }
});

document.querySelectorAll(".rule-resource").forEach(resource => {
  let page = 1, query = "", loaded = false;
  const search = resource.querySelector("form");
  const status = resource.querySelector(".rule-status");
  const previous = resource.querySelector('[data-page="previous"]');
  const next = resource.querySelector('[data-page="next"]');
  let pending = false;
  async function load() {
    if (pending) return;
    pending = true;
    search.querySelector("button").disabled = previous.disabled = next.disabled = true;
    status.textContent = "Loading rules…";
    try {
      const url = new URL(resource.dataset.path, location.origin);
      url.searchParams.set("page", page);
      url.searchParams.set("q", query);
      const response = await fetch(url, { cache: "no-store" });
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json();
      const lines = resource.querySelector(".rule-lines");
      lines.replaceChildren(...data.lines.map(line => {
        const item = document.createElement("li");
        item.textContent = line;
        return item;
      }));
      lines.start = (data.page - 1) * 100 + 1;
      resource.querySelector(".page-label").textContent = `Page ${data.page} / ${data.pages}`;
      status.textContent = `${data.total.toLocaleString()} matching rules`;
      previous.disabled = data.page <= 1;
      next.disabled = data.page >= data.pages;
      loaded = true;
    } catch (error) {
      status.textContent = error.message || "Rules could not be loaded.";
    } finally {
      pending = false;
      search.querySelector("button").disabled = false;
    }
  }
  resource.addEventListener("toggle", () => { if (resource.open && !loaded) load(); });
  search.addEventListener("submit", event => {
    event.preventDefault();
    if (pending) return;
    query = search.elements.q.value;
    page = 1;
    load();
  });
  previous.addEventListener("click", () => { page--; load(); });
  next.addEventListener("click", () => { page++; load(); });
});
