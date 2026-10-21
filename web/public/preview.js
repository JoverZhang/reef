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
