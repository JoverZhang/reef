import { randomUUID } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { ruleSummary, type RuleResource, type Snapshot, type CachedSnapshot } from "./subscription.ts";
import { comparisonBaseline, compare, changeSummary, displayHistoryLines, type Baseline, type HistorySummary, type HistoryEntry, type HistoryOverview, type HistoryPage } from "./history.ts";

export const FRESH_MS = 60 * 60 * 1000;
const RETAIN_SECONDS = 24 * 60 * 60;
const LOCK_MS = 240_000;
type Command = (...args: (string | number)[]) => Promise<unknown>;
type Entry = { id: string; snapshot: CachedSnapshot };
type Failure = { id: string; message: string };
export type CacheState = { snapshot: CachedSnapshot | Snapshot | null; error: string | null; fresh: boolean; history?: HistoryOverview };
export type CachedRule = { resource: RuleResource | null; updatedAt: string };

export class RefreshError extends Error {}

function snapshotIsFresh(updatedAt: string | null | undefined, now: number): updatedAt is string {
  return !!updatedAt && now - Date.parse(updatedAt) < FRESH_MS;
}

export function memorySnapshotLoader(compile: () => Promise<Snapshot>, now = Date.now) {
  let snapshot: Snapshot | null = null;
  let error: string | null = null;
  let pending: Promise<void> | undefined;

  async function refresh() {
    try {
      const compiled = await compile();
      snapshot = { ...compiled, updatedAt: new Date(now()).toISOString() };
      error = null;
    } catch (failure) {
      error = failure instanceof RefreshError ? failure.message : "Subscription refresh failed.";
    }
  }

  async function load(force = false, includeHistory = true) {
    if (force || !snapshotIsFresh(snapshot?.updatedAt, now())) {
      pending ??= refresh().finally(() => { pending = undefined; });
      await pending;
    }
    if (snapshot && now() - Date.parse(snapshot.updatedAt) >= RETAIN_SECONDS * 1000) snapshot = null;
    return { snapshot, error, fresh: snapshotIsFresh(snapshot?.updatedAt, now()),
      history: includeHistory ? { count: 0, latest: null, unavailable: true } : undefined };
  }

  return Object.assign(load, {
    history: undefined,
    async rule(id: string): Promise<CachedRule> {
      const { snapshot, fresh, error } = await load(false, false);
      if (!fresh || !snapshot) throw new RefreshError(error ?? "A current snapshot is unavailable.");
      return { resource: snapshot.resources?.find(rule => rule.id === id) ?? null, updatedAt: snapshot.updatedAt };
    },
  });
}

export function redisCommand(env: NodeJS.ProcessEnv = process.env): Command {
  const url = env.KV_REST_API_URL ?? env.UPSTASH_REDIS_REST_URL;
  const token = env.KV_REST_API_TOKEN ?? env.UPSTASH_REDIS_REST_TOKEN;
  return async (...args) => {
    if (!url || !token) throw new RefreshError("Connect Upstash Redis to this deployment before loading subscriptions.");
    try {
      const response = await fetch(url, {
        method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(args), cache: "no-store", signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error();
      const result = await response.json();
      if (result.error) throw new Error();
      return result.result;
    } catch {
      throw new RefreshError("Shared cache is unavailable. Check the Redis integration.");
    }
  };
}

// Swap in the complete snapshot only after the new hash has been written.
const PUBLISH = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[4], unpack(ARGV, 3))
redis.call('EXPIRE', KEYS[4], ARGV[2])
redis.call('RENAME', KEYS[4], KEYS[2])
redis.call('DEL', KEYS[3])
return 1`;
const SAVE_HISTORY = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[2], ARGV[2])
if ARGV[3] ~= '' then
  redis.call('SET', KEYS[4], ARGV[3])
  redis.call('LPUSH', KEYS[3], ARGV[4])
  local expired = redis.call('LRANGE', KEYS[3], 50, -1)
  for _, value in ipairs(expired) do
    redis.call('DEL', KEYS[3] .. ':' .. cjson.decode(value).id)
  end
  redis.call('LTRIM', KEYS[3], 0, 49)
end
return 1`;
const FAIL = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[2], ARGV[2], 'EX', 3600)
redis.call('DEL', KEYS[1])
return 1`;
const RELEASE = `
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0`;

const encode = (value: unknown) => gzipSync(JSON.stringify(value)).toString("base64");
function decode<T>(value: string): T {
  return JSON.parse(gunzipSync(Buffer.from(value, "base64"), { maxOutputLength: 128 * 1024 * 1024 }).toString());
}

export function snapshotLoader({ command, namespace, historyNamespace = namespace, compile, now = Date.now,
  wait = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)),
}: {
  command: Command; namespace: string; historyNamespace?: string; compile: () => Promise<Snapshot>;
  now?: () => number; wait?: (ms: number) => Promise<void>;
}) {
  const key = `reef:${namespace}:snapshot`, failureKey = `${key}:error`;
  const historyKey = `reef:${historyNamespace}:history`, baselineKey = `${historyKey}:baseline`, lock = `${historyKey}:lock`;
  const fresh = (updatedAt?: string | null): updatedAt is string => snapshotIsFresh(updatedAt, now());
  async function state(entry: Entry | null, failure: Failure | null, includeHistory: boolean): Promise<CacheState> {
    const snapshot = entry?.snapshot ?? null;
    const current: CacheState = { snapshot, error: failure?.message ?? null, fresh: fresh(snapshot?.updatedAt) };
    if (includeHistory) {
      try {
        const [count, latest] = await command("EVAL", "return {redis.call('LLEN', KEYS[1]), redis.call('LINDEX', KEYS[1], 0)}", 1, historyKey) as [number, string | null];
        current.history = { count, latest: latest ? JSON.parse(latest) : null };
      } catch {
        current.history = { count: 0, latest: null, unavailable: true };
      }
    }
    return current;
  }
  async function read(): Promise<[Entry | null, Failure | null]> {
    const [value, error] = await command("EVAL", "return {redis.call('HGET', KEYS[1], 'entry'), redis.call('GET', KEYS[2])}", 2, key, failureKey) as (string | null)[];
    try {
      return [value ? decode<Entry>(value) : null,
        error ? JSON.parse(error) : null];
    } catch {
      throw new RefreshError("Shared snapshot could not be read. Republish to start a new cache.");
    }
  }
  async function load(force = false, includeHistory = true): Promise<CacheState> {
    const [initial, initialFailure] = await read();
    if (!force && fresh(initial?.snapshot.updatedAt)) return state(initial, initialFailure, includeHistory);
    // Leave enough of the function's 300-second budget for a compilation after waiting.
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      const token = randomUUID();
      if (await command("SET", lock, token, "NX", "PX", LOCK_MS)) {
        let current: Entry | null, previousFailure: Failure | null;
        try { [current, previousFailure] = await read(); }
        catch (error) {
          await command("EVAL", RELEASE, 1, lock, token);
          throw error;
        }
        if (current?.id !== initial?.id || previousFailure?.id !== initialFailure?.id || (!force && fresh(current?.snapshot.updatedAt))) {
          await command("EVAL", RELEASE, 1, lock, token);
          return state(current, previousFailure, includeHistory);
        }
        let snapshot: Snapshot, entry: Entry;
        try {
          snapshot = await compile();
          snapshot.updatedAt = new Date(now()).toISOString();
          const resources = snapshot.resources ?? [];
          entry = { id: randomUUID(), snapshot: { ...snapshot, resources: resources.map(ruleSummary) } };
          const published = await command("EVAL", PUBLISH, 4, lock, key, failureKey, `${key}:pending:${token}`,
            token, RETAIN_SECONDS, "updatedAt", snapshot.updatedAt, "entry", encode(entry),
            ...resources.flatMap(resource => [`rule:${resource.id}`, encode(resource)]));
          if (published !== 1) throw new RefreshError("Refresh ownership expired. Retry the request.");
        } catch (error) {
          const failure: Failure = { id: randomUUID(), message: error instanceof RefreshError
            ? error.message : "Subscription refresh failed. Retry after checking the configured sources." };
          await command("EVAL", FAIL, 2, lock, failureKey, token, JSON.stringify(failure));
          return state(current, failure, includeHistory);
        }
        try {
          const previous = await command("GET", baselineKey) as string | null;
          const baseline = comparisonBaseline(snapshot);
          const lines = compare(previous ? decode<Baseline>(previous) : null, baseline);
          const summary = changeSummary(entry.id, snapshot.updatedAt, force ? "Manual refresh" : !current && previous ? "Deployment refresh" : "Automatic refresh", lines);
          await command("EVAL", SAVE_HISTORY, 4, lock, baselineKey, historyKey, `${historyKey}:${entry.id}`,
            token, encode(baseline), lines.length ? encode({ ...summary, lines }) : "", JSON.stringify(summary));
        } catch {
          // The snapshot is usable even when the history comparison or write fails.
        } finally {
          await command("EVAL", RELEASE, 1, lock, token).catch(() => {});
        }
        return state(entry, null, includeHistory);
      }
      await wait(500);
      if (await command("GET", lock)) continue;
      const [current, failure] = await read();
      if (current?.id !== initial?.id || failure?.id !== initialFailure?.id) return state(current, failure, includeHistory);
    }
    throw new RefreshError("A refresh is still running. Retry shortly.");
  }
  return Object.assign(load, {
    async rule(id: string): Promise<CachedRule> {
      const readRule = () => command("HMGET", key, "updatedAt", `rule:${id}`) as Promise<[string | null, string | null]>;
      let [updatedAt, value] = await readRule();
      if (!fresh(updatedAt)) {
        const current = await load(false, false);
        if (!current.fresh) throw new RefreshError(current.error ?? "A current snapshot is unavailable.");
        [updatedAt, value] = await readRule();
        if (!fresh(updatedAt)) throw new RefreshError("A current snapshot is unavailable.");
      }
      return { resource: value ? decode<RuleResource>(value) : null, updatedAt };
    },
    async history(page = 1, id?: string): Promise<HistoryPage> {
      if (id) {
        const value = await command("GET", `${historyKey}:${id}`) as string | null;
        if (!value) return { entries: [], page, pages: 1, total: 0 };
        const { lines, ...entry } = decode<HistoryEntry>(value);
        return { entry, lines: displayHistoryLines(lines.slice((page - 1) * 200, page * 200)), page,
          pages: Math.max(1, Math.ceil(lines.length / 200)), total: lines.length };
      }
      const [values, total] = await command("EVAL", "return {redis.call('LRANGE', KEYS[1], ARGV[1], ARGV[2]), redis.call('LLEN', KEYS[1])}",
        1, historyKey, (page - 1) * 10, page * 10 - 1) as [string[], number];
      return { entries: values.map(value => JSON.parse(value) as HistorySummary), page, pages: Math.max(1, Math.ceil(total / 10)), total };
    },
  });
}
