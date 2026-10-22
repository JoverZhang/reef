import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";
import { subscriptionService } from "../web/lib/service.ts";
import { snapshotLoader, redisCommand, RefreshError, FRESH_MS } from "../web/lib/cache.ts";

const password = "fictional-runtime-password";
const bootstrap = { passwordHash: createHash("sha256").update(password).digest("hex"), poolIds: [] };
function snapshot() {
  return {
    updatedAt: new Date().toISOString(), passwordHash: bootstrap.passwordHash,
    exits: [], otherNodes: [], pools: [], proxies: [], groups: [{ name: "PROXY", type: "select", proxies: ["DIRECT"] }],
    templates: { clash: { rules: ["MATCH,PROXY"] }, "clash-geo": {
      "rule-providers": { sample: { url: "reef-resource:clash-geo/sample", interval: 3600 } },
      rules: ["RULE-SET,sample,PROXY", "MATCH,PROXY"],
    } },
    qx: { body: "[filter_remote]\nreef-resource:qx/sample, tag=sample\n", choices: [], error: null, relay: null },
    resources: [
      { id: "clash-geo/sample", name: "sample", profile: "clash-geo", policy: "PROXY", reinject: false,
        lines: Array.from({ length: 205 }, (_, n) => `DOMAIN,host${n}.example.invalid`) },
      { id: "qx/sample", name: "sample", profile: "qx", policy: "Reef", reinject: true,
        lines: ["host, service.example.invalid, Reef, via-interface=%TUN%"] },
    ],
  };
}
const request = (path, key = password) => new Request(`https://reef.example.invalid${path}${path.includes("?") ? "&" : "?"}password=${key}`);
const post = key => new Request("https://reef.example.invalid/refresh", {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: key }),
});

test("authentication and query validation run before any cache or upstream operation", async () => {
  const service = subscriptionService(bootstrap, () => { throw new Error("Loader must not run"); });
  for (const key of ["", "wrong", `${password}&password=${password}`]) {
    assert.equal((await service.serve(request("/", key), false)).status, 404);
    assert.equal((await service.serve(request("/dump", key), true)).status, 404);
    assert.equal((await service.rules(request("/rules/qx/sample", key), "qx/sample")).status, 404);
  }
  assert.equal((await service.refresh(post("wrong"))).status, 404);
  assert.equal((await service.serve(request("/?include99=sample"), false)).status, 400);
  assert.equal((await service.rules(request("/rules/qx/sample?token=invalid"), "qx/sample")).status, 400);
});

test("preview, export, hosted rules, search, and pagination share one complete snapshot", async () => {
  const data = snapshot(), original = JSON.stringify(data);
  const service = subscriptionService(bootstrap, async () => ({ snapshot: data, fresh: true, error: null }));
  const page = await service.serve(request("/"), false);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Force update/);
  assert.match(html, /205 rules/);
  assert.doesNotMatch(html, /host204\.example/);
  const output = await service.serve(request("/dump"), true);
  assert.match(await output.text(), /https:\/\/reef\.example\.invalid\/rules\/clash-geo\/sample\?password=/);
  const qx = await service.serve(request("/dump?type=qx"), true);
  assert.match(await qx.text(), /https:\/\/reef\.example\.invalid\/rules\/qx\/sample\?password=/);
  const rules = await service.rules(request("/rules/qx/sample"), "qx/sample");
  assert.equal(await rules.text(), "host, service.example.invalid, Reef, via-interface=%TUN%\n");
  const paged = await service.rules(request("/rules/clash-geo/sample?format=json&page=3"), "clash-geo/sample");
  assert.deepEqual((await paged.json()).lines, data.resources[0].lines.slice(200));
  const searched = await service.rules(request("/rules/clash-geo/sample?format=json&q=HOST204"), "clash-geo/sample");
  assert.equal((await searched.json()).total, 1);
  assert.match(page.headers.get("cache-control"), /no-store/);
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");
  assert.equal(JSON.stringify(data), original, "Requests must never mutate the shared snapshot");
});

test("failed refresh retains preview but expired data cannot be exported as success", async () => {
  for (const fresh of [false, true]) {
    const service = subscriptionService(bootstrap, async () => ({ snapshot: snapshot(), fresh, error: "upstream URL #2 fetch failed" }));
    const page = await service.serve(request("/"), false);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /upstream URL #2 fetch failed/);
    assert.equal((await service.serve(request("/dump"), true)).status, fresh ? 200 : 502);
    assert.equal((await service.rules(request("/rules/qx/sample"), "qx/sample")).status, fresh ? 200 : 502);
    assert.equal((await service.refresh(post(password))).status, 502);
  }
  const empty = subscriptionService(bootstrap, async () => { throw new RefreshError("Connect Redis"); });
  const page = await empty.serve(request("/"), false);
  assert.equal(page.status, 502);
  const html = await page.text();
  assert.match(html, /No successful update yet/);
  assert.doesNotMatch(html, /Invalid Date/);
});

test("force update is an authenticated same-origin POST and hides unexpected errors", async () => {
  let forced;
  const service = subscriptionService(bootstrap, async force => { forced = force; return { snapshot: snapshot(), fresh: true, error: null }; });
  assert.equal((await service.refresh(post(password))).status, 200);
  assert.equal(forced, true);
  const proxied = new Request(`http://localhost/dump?password=${password}`, {
    headers: { host: "reef.example.invalid", "x-forwarded-proto": "https" },
  });
  assert.match(await (await service.serve(proxied, true)).text(), /https:\/\/reef\.example\.invalid\/rules\//);
  const proxiedPost = new Request("http://localhost/refresh", {
    method: "POST", headers: { host: "reef.example.invalid", "x-forwarded-proto": "https", origin: "https://reef.example.invalid" },
    body: JSON.stringify({ password }),
  });
  assert.equal((await service.refresh(proxiedPost)).status, 200);
  const foreign = post(password);
  foreign.headers.set("origin", "https://another.example.invalid");
  assert.equal((await service.refresh(foreign)).status, 403);
  const broken = subscriptionService(bootstrap, async () => { throw new Error("private-credential"); });
  const error = await broken.serve(request("/dump"), true);
  assert.equal(error.status, 500);
  assert.doesNotMatch(await error.text(), /private-credential/);
});

test("Redis credentials are required and never included in errors", async () => {
  await assert.rejects(redisCommand({})("GET", "sample"), /Connect Upstash Redis/);
  await assert.rejects(redisCommand({ KV_REST_API_URL: "invalid-private-url", KV_REST_API_TOKEN: "private-token" })("GET", "sample"),
    error => error.message === "Shared cache is unavailable. Check the Redis integration.");
});

// Run the distributed-cache tests against a disposable Redis container, not a
// mock of Lua/SET NX behavior: REEF_TEST_REDIS_CONTAINER=<container name>.
const container = process.env.REEF_TEST_REDIS_CONTAINER;
const cacheOptions = { skip: !container };
const exec = promisify(execFile);
const command = async (...args) => {
  const { stdout } = await exec("docker", ["exec", container, "redis-cli", "--json", ...args.map(String)]);
  const result = JSON.parse(stdout);
  if (result && result.error) throw new Error(result.error);
  return result;
};

test("Redis coalesces independent workers and namespaces deployments", cacheOptions, async () => {
  const namespace = randomUUID();
  let calls = 0;
  const compile = async () => { calls++; await new Promise(resolve => setTimeout(resolve, 100)); return snapshot(); };
  const first = snapshotLoader({ command, namespace, compile });
  const second = snapshotLoader({ command, namespace, compile });
  const states = await Promise.all([first(), second(), first(true), second(true)]);
  assert.equal(calls, 1);
  assert.equal(new Set(states.map(state => state.snapshot.updatedAt)).size, 1);
  await second();
  assert.equal(calls, 1);
  await snapshotLoader({ command, namespace: randomUUID(), compile })();
  assert.equal(calls, 2);
});

test("Redis freshness is measured from success; errors preserve the previous timestamp", cacheOptions, async () => {
  let now = Date.now(), calls = 0, failing = false;
  const load = snapshotLoader({ command, namespace: randomUUID(), now: () => now, compile: async () => {
    calls++;
    if (failing) throw new RefreshError("upstream URL #2 fetch failed");
    return snapshot();
  } });
  const original = (await load()).snapshot.updatedAt;
  now += FRESH_MS - 1;
  assert.equal((await load()).snapshot.updatedAt, original);
  assert.equal(calls, 1);
  failing = true;
  const failed = await load(true);
  assert.equal(failed.snapshot.updatedAt, original);
  assert.equal(failed.fresh, true);
  now++;
  const stale = await load();
  assert.equal(stale.fresh, false);
  assert.equal(stale.snapshot.updatedAt, original);
  failing = false;
  const updated = await load();
  assert.equal(updated.fresh, true);
  assert.equal(updated.error, null);
  assert.notEqual(updated.snapshot.updatedAt, original);
});

test("an expired worker cannot overwrite data or release another worker's lock", cacheOptions, async () => {
  const namespace = randomUUID();
  let started, finish;
  const compiling = new Promise(resolve => { started = resolve; });
  const pending = new Promise(resolve => { finish = resolve; });
  const old = snapshotLoader({ command, namespace, compile: async () => { started(); await pending; return snapshot(); } });
  const oldRequest = old();
  await compiling;
  const lock = `reef:${namespace}:snapshot:lock`;
  await command("PEXPIRE", lock, 1);
  await new Promise(resolve => setTimeout(resolve, 10));
  const replacement = snapshotLoader({ command, namespace, compile: async () => {
    const data = snapshot(); data.otherNodes = [{ name: "New endpoint" }]; return data;
  } });
  const newState = await replacement();
  finish();
  assert.match((await oldRequest).error, /ownership expired/);
  assert.deepEqual((await replacement()).snapshot, newState.snapshot);
});
