import { randomUUID } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import type { Snapshot } from "./subscription.ts";
import { comparisonBaseline, compare, changeSummary, displayHistoryLines, type Baseline, type HistorySummary, type HistoryEntry, type HistoryOverview, type HistoryPage } from "./history.ts";

export const FRESH_MS = 60 * 60 * 1000;
const RETAIN_SECONDS = 24 * 60 * 60;
const LOCK_MS = 240_000;
type Command = (...args: (string | number)[]) => Promise<unknown>;
type Entry = { id: string; snapshot: Snapshot };
type Failure = { id: string; message: string };
export type CacheState = { snapshot: Snapshot | null; error: string | null; fresh: boolean; history?: HistoryOverview };

export class RefreshError extends Error {}

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

// The token check and publication are one Redis operation. An expired worker
// cannot overwrite a newer snapshot or release another worker's lock.
const PUBLISH = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[4], ARGV[4])
if ARGV[5] ~= '' then
  redis.call('SET', KEYS[6], ARGV[5])
  redis.call('LPUSH', KEYS[5], ARGV[6])
  local expired = redis.call('LRANGE', KEYS[5], 50, -1)
  for _, value in ipairs(expired) do
    redis.call('DEL', KEYS[5] .. ':' .. cjson.decode(value).id)
  end
  redis.call('LTRIM', KEYS[5], 0, 49)
end
redis.call('DEL', KEYS[3])
redis.call('DEL', KEYS[1])
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
  const fresh = (entry: Entry | null) => !!entry && now() - Date.parse(entry.snapshot.updatedAt) < FRESH_MS;
  async function state(entry: Entry | null, failure: Failure | null): Promise<CacheState> {
    const [count, latest] = await command("EVAL", "return {redis.call('LLEN', KEYS[1]), redis.call('LINDEX', KEYS[1], 0)}", 1, historyKey) as [number, string | null];
    return { snapshot: entry?.snapshot ?? null, error: failure?.message ?? null, fresh: fresh(entry),
      history: { count, latest: latest ? JSON.parse(latest) : null } };
  }
  async function read(): Promise<[Entry | null, Failure | null]> {
    const [value, error] = await command("MGET", key, failureKey) as (string | null)[];
    try {
      return [value ? decode<Entry>(value) : null,
        error ? JSON.parse(error) : null];
    } catch {
      throw new RefreshError("Shared snapshot could not be read. Republish to start a new cache.");
    }
  }
  async function load(force = false): Promise<CacheState> {
    const [initial, initialFailure] = await read();
    if (!force && fresh(initial)) return state(initial, initialFailure);
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
        if (current?.id !== initial?.id || previousFailure?.id !== initialFailure?.id || (!force && fresh(current))) {
          await command("EVAL", RELEASE, 1, lock, token);
          return state(current, previousFailure);
        }
        try {
          const previous = await command("GET", baselineKey) as string | null;
          const snapshot = await compile();
          snapshot.updatedAt = new Date(now()).toISOString();
          const entry: Entry = { id: randomUUID(), snapshot };
          const baseline = comparisonBaseline(snapshot);
          const lines = compare(previous ? decode<Baseline>(previous) : null, baseline);
          const summary = changeSummary(entry.id, snapshot.updatedAt, force ? "Manual refresh" : !current && previous ? "Deployment refresh" : "Automatic refresh", lines);
          const published = await command("EVAL", PUBLISH, 6, lock, key, failureKey, baselineKey, historyKey, `${historyKey}:${entry.id}`,
            token, encode(entry), RETAIN_SECONDS, encode(baseline), lines.length ? encode({ ...summary, lines }) : "", JSON.stringify(summary));
          if (published !== 1) throw new RefreshError("Refresh ownership expired. Retry the request.");
          return state(entry, null);
        } catch (error) {
          const failure: Failure = { id: randomUUID(), message: error instanceof RefreshError
            ? error.message : "Subscription refresh failed. Retry after checking the configured sources." };
          await command("EVAL", FAIL, 2, lock, failureKey, token, JSON.stringify(failure));
          return state(current, failure);
        }
      }
      await wait(500);
      if (await command("GET", lock)) continue;
      const [current, failure] = await read();
      if (current?.id !== initial?.id || failure?.id !== initialFailure?.id) return state(current, failure);
    }
    throw new RefreshError("A refresh is still running. Retry shortly.");
  }
  return Object.assign(load, {
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
