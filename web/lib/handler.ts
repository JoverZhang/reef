import "server-only";
import { snapshot } from "../generated/snapshot";
import { dump, RequestError, select } from "./subscription";
import { previewHtml } from "./preview";

const headers = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "X-Content-Type-Options": "nosniff",
};

export function serve(request: Request, download: boolean): Response {
  try {
    const params = new URL(request.url).searchParams;
    const selection = select(snapshot, params);
    const body = download ? dump(snapshot, selection) : previewHtml(selection.preview, params);
    const contentType = download
      ? selection.preview.type === "qx" ? "text/plain; charset=utf-8" : "text/yaml; charset=utf-8"
      : "text/html; charset=utf-8";
    return new Response(body, { headers: { ...headers, "Content-Type": contentType } });
  } catch (error) {
    const status = error instanceof RequestError ? error.status : 500;
    const message = error instanceof RequestError ? error.message : "Subscription generation failed.";
    // Never log an exception containing a request URL, snapshot, or node credentials.
    return new Response(message + "\n", {
      status, headers: { ...headers, "Content-Type": "text/plain; charset=utf-8" },
    });
  }
}
