import { randomUUID } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import type { Snapshot } from "./subscription.ts";

export const FRESH_MS = 60 * 60 * 1000;
const RETAIN_SECONDS = 24 * 60 * 60;
const LOCK_MS = 240_000;
type Command = (...args: (string | number)[]) => Promise<unknown>;
type Entry = { id: string; snapshot: Snapshot };
type Failure = { id: string; message: string };
export type CacheState = { snapshot: Snapshot | null; error: string | null; fresh: boolean };

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

export function snapshotLoader({ command, namespace, compile, now = Date.now,
  wait = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)),
}: {
  command: Command; namespace: string; compile: () => Promise<Snapshot>;
  now?: () => number; wait?: (ms: number) => Promise<void>;
}) {
  const key = `reef:${namespace}:snapshot`, failureKey = `${key}:error`, lock = `${key}:lock`;
  const fresh = (entry: Entry | null) => !!entry && now() - Date.parse(entry.snapshot.updatedAt) < FRESH_MS;
  const state = (entry: Entry | null, failure: Failure | null): CacheState => ({
    snapshot: entry?.snapshot ?? null, error: failure?.message ?? null, fresh: fresh(entry),
  });
  async function read(): Promise<[Entry | null, Failure | null]> {
    const [value, error] = await command("MGET", key, failureKey) as (string | null)[];
    try {
      return [value ? JSON.parse(gunzipSync(Buffer.from(value, "base64"), { maxOutputLength: 64 * 1024 * 1024 }).toString()) : null,
        error ? JSON.parse(error) : null];
    } catch {
      throw new RefreshError("Shared snapshot could not be read. Republish to start a new cache.");
    }
  }
  return async function load(force = false): Promise<CacheState> {
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
          const snapshot = await compile();
          snapshot.updatedAt = new Date(now()).toISOString();
          const entry: Entry = { id: randomUUID(), snapshot };
          const encoded = gzipSync(JSON.stringify(entry)).toString("base64");
          const published = await command("EVAL", PUBLISH, 3, lock, key, failureKey, token, encoded, RETAIN_SECONDS);
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
  };
}
