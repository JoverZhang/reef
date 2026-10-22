import { stringify } from "yaml";
import { RefreshError, type CacheState } from "./cache.ts";
import { authenticate, validateQuery, select, dump, RequestError, selectionModel, type Preview } from "./subscription.ts";
import type { HistoryPage } from "./history.ts";
import { previewHtml } from "./preview.ts";

const headers = {
  "Cache-Control": "private, no-store, max-age=0", "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow, noarchive", "X-Content-Type-Options": "nosniff",
};
function response(body: string, status = 200, type = "text/plain; charset=utf-8") {
  return new Response(body, { status, headers: { ...headers, "Content-Type": type } });
}
function errorResponse(error: unknown) {
  // Never include raw exceptions, request URLs, or compiler input in responses or logs.
  const known = error instanceof RequestError || error instanceof RefreshError;
  return response((known ? error.message : "Subscription generation failed.") + "\n",
    error instanceof RequestError ? error.status : error instanceof RefreshError ? 502 : 500);
}

function requestOrigin(request: Request): string {
  // Next.js may normalize request.url to localhost behind its HTTP adapter.
  const url = new URL(request.url);
  url.host = request.headers.get("host") ?? url.host;
  const protocol = request.headers.get("x-forwarded-proto")?.split(",")[0].trim();
  if (protocol === "https" || protocol === "http") url.protocol = protocol + ":";
  return url.origin;
}

export function subscriptionService(
  bootstrap: { passwordHash: string; poolIds: string[] },
  load: (force?: boolean) => Promise<CacheState>,
  readHistory?: (page: number, id?: string) => Promise<HistoryPage>,
) {
  const auth = (params: URLSearchParams) => authenticate(bootstrap.passwordHash, params);
  const data = (state: CacheState) => ({
    model: state.snapshot ? selectionModel(state.snapshot) : null,
    cache: { fresh: state.fresh, error: state.error },
    history: state.history ?? { count: 0, latest: null },
  });
  return {
    async serve(request: Request, download: boolean): Promise<Response> {
      try {
        const url = new URL(request.url), params = url.searchParams;
        auth(params);
        const type = validateQuery(params, bootstrap.poolIds);
        let state: CacheState;
        try { state = await load(); }
        catch (error) {
          if (!(error instanceof RefreshError)) throw error;
          state = { snapshot: null, fresh: false, error: error.message };
        }
        if (download && (!state.fresh || !state.snapshot)) {
          throw new RequestError(502, state.error ?? "A current snapshot is unavailable.");
        }
        const selection = state.snapshot ? select(state.snapshot, params) : null;
        if (download && selection && state.snapshot) {
          return response(dump(state.snapshot, selection, { origin: requestOrigin(request), password: params.get("password")! }),
            200, type === "qx" ? "text/plain; charset=utf-8" : "text/yaml; charset=utf-8");
        }
        const preview: Preview = selection?.preview ?? {
          type, updatedAt: "", exits: [], otherNodes: [], pools: [], choices: [], relays: [], errors: [],
        };
        preview.cache = { fresh: state.fresh, error: state.error };
        if (!state.fresh) preview.errors.push(state.error ?? "A current snapshot is unavailable.");
        return response(previewHtml(preview, params, data(state)), state.snapshot ? 200 : 502, "text/html; charset=utf-8");
      } catch (error) { return errorResponse(error); }
    },

    async refresh(request: Request): Promise<Response> {
      try {
        let body;
        try { body = await request.json(); }
        catch { throw new RequestError(404, "Not found"); }
        auth(new URLSearchParams({ password: typeof body?.password === "string" ? body.password : "" }));
        if (Object.keys(body).some(key => key !== "password")) throw new RequestError(400, "Unknown refresh parameter.");
        if (request.headers.has("origin") && request.headers.get("origin") !== requestOrigin(request)) {
          throw new RequestError(403, "Refresh must originate from this site.");
        }
        const state = await load(true);
        if (state.error || !state.fresh || !state.snapshot) {
          return response(JSON.stringify({ ...data(state), error: state.error ?? "Refresh did not produce a current snapshot." }), 502, "application/json");
        }
        return response(JSON.stringify({ updatedAt: state.snapshot.updatedAt, ...data(state) }), 200, "application/json");
      } catch (error) { return errorResponse(error); }
    },

    async history(request: Request): Promise<Response> {
      try {
        const params = new URL(request.url).searchParams;
        auth(params);
        for (const key of params.keys()) {
          if (!["password", "page", "id"].includes(key) || params.getAll(key).length !== 1) {
            throw new RequestError(400, "Invalid history query parameter.");
          }
        }
        const page = params.get("page") ?? "1", id = params.get("id") ?? undefined;
        if (!/^[1-9][0-9]{0,6}$/.test(page) || (id !== undefined && !/^[a-f0-9-]{36}$/.test(id))) {
          throw new RequestError(400, "Invalid history page or entry.");
        }
        if (!readHistory) throw new RefreshError("Update history is unavailable.");
        const result = await readHistory(Number(page), id);
        if (id && !("entry" in result)) throw new RequestError(404, "History entry is no longer available.");
        return response(JSON.stringify(result), 200, "application/json");
      } catch (error) { return errorResponse(error); }
    },

    async rules(request: Request, id: string): Promise<Response> {
      try {
        const params = new URL(request.url).searchParams;
        auth(params);
        const preview = params.get("format") === "json";
        const allowed = new Set(preview ? ["password", "format", "q", "page"] : ["password"]);
        for (const key of params.keys()) {
          if (!allowed.has(key) || params.getAll(key).length !== 1) {
            throw new RequestError(400, "Invalid rule query parameter.");
          }
        }
        const pageText = params.get("page") ?? "1";
        if (!/^[1-9][0-9]{0,6}$/.test(pageText)) throw new RequestError(400, "Invalid rule page.");
        const state = await load();
        if (!state.fresh || !state.snapshot) throw new RequestError(502, state.error ?? "A current snapshot is unavailable.");
        const resource = state.snapshot.resources?.find(resource => resource.id === id);
        if (!resource) throw new RequestError(404, "Not found");
        if (preview) {
          const query = (params.get("q") ?? "").toLowerCase();
          const lines = query ? resource.lines.filter(line => line.toLowerCase().includes(query)) : resource.lines;
          const page = Number(pageText);
          return response(JSON.stringify({ lines: lines.slice((page - 1) * 100, page * 100), page,
            total: lines.length, pages: Math.max(1, Math.ceil(lines.length / 100)), updatedAt: state.snapshot.updatedAt }),
          200, "application/json");
        }
        return resource.profile === "qx"
          ? response(resource.lines.join("\n") + "\n")
          : response(stringify({ payload: resource.lines }, { lineWidth: 0 }), 200, "text/yaml; charset=utf-8");
      } catch (error) { return errorResponse(error); }
    },
  };
}
