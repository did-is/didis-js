import { test } from "node:test";
import assert from "node:assert/strict";
import { DidisClient, DidisError, DEFAULT_BASE_URL } from "../dist/index.js";

function mock(responses) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    const r = responses.shift() ?? { status: 200, body: {} };
    return new Response(JSON.stringify(r.body), { status: r.status, headers: r.headers ?? { "content-type": "application/json" } });
  };
  return { calls, fetchImpl };
}

test("defaults to the public DID.is API", async () => {
  assert.equal(DEFAULT_BASE_URL, "https://did.is/api");
  const { calls, fetchImpl } = mock([{ status: 200, body: { status: "ok" } }]);
  await new DidisClient({ fetch: fetchImpl }).health();
  assert.equal(calls[0].url, "https://did.is/api/health");
});

test("percent-encodes identifiers exactly once", async () => {
  const { calls, fetchImpl } = mock([{ status: 200, body: {} }]);
  await new DidisClient({ baseUrl: "http://x/", fetch: fetchImpl }).resolve("did:web:example.com%3A8443", { noCache: true });
  assert.equal(calls[0].url, "http://x/v1/resolve/did%3Aweb%3Aexample.com%253A8443?noCache=true");
});

test("query-string inspectors and POST bodies", async () => {
  const { calls, fetchImpl } = mock([]);
  const c = new DidisClient({ baseUrl: "http://x", fetch: fetchImpl });
  await c.inspectMcp("https://mcp.example.com/mcp?a=b");
  await c.fastVerifyJws("a.b.c", "authentication");
  assert.equal(calls[0].url, "http://x/v1/mcp/inspect?endpoint=https%3A%2F%2Fmcp.example.com%2Fmcp%3Fa%3Db");
  assert.equal(calls[1].init.method, "POST");
  assert.deepEqual(JSON.parse(calls[1].init.body), { jws: "a.b.c", relationship: "authentication" });
});

test("non-2xx throws DidisError with RFC 9457 problem and Retry-After", async () => {
  const { fetchImpl } = mock([{ status: 429, body: { type: "t", title: "Too many", detail: "slow down", code: "RATE_LIMITED" }, headers: { "content-type": "application/problem+json", "retry-after": "7" } }]);
  await assert.rejects(new DidisClient({ fetch: fetchImpl, retry: false }).fastVerifyDid("did:key:z"), (e) => {
    assert.ok(e instanceof DidisError);
    assert.equal(e.status, 429);
    assert.equal(e.problem.code, "RATE_LIMITED");
    assert.equal(e.problem.retryAfter, "7");
    return true;
  });
});

test("admin routes refuse to run without a token", async () => {
  const { calls, fetchImpl } = mock([]);
  await assert.rejects(new DidisClient({ fetch: fetchImpl }).watches(), /adminToken/);
  assert.equal(calls.length, 0);
});

test("identifies itself as didis-client with the package version", async () => {
  const { calls, fetchImpl } = mock([{ status: 200, body: {} }, { status: 200, body: {} }]);
  const { VERSION } = await import("../dist/index.js");
  const pkg = JSON.parse(await (await import("node:fs/promises")).readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(VERSION, pkg.version);
  const c = new DidisClient({ fetch: fetchImpl });
  await c.health();
  await c.verifyCredential({}).catch(() => {});
  for (const call of calls) assert.equal(call.init.headers["user-agent"], `didis-client/${pkg.version}`);
});

test("waits out a 429 with Retry-After and retries (bounded, can be disabled)", async () => {
  const limited = { status: 429, body: { title: "Rate limited", detail: "wait", code: "RATE_LIMITED" }, headers: { "content-type": "application/problem+json", "retry-after": "0" } };
  let m = mock([limited, { status: 200, body: { status: "ok" } }]);
  assert.deepEqual(await new DidisClient({ fetch: m.fetchImpl }).health(), { status: "ok" });
  assert.equal(m.calls.length, 2);

  // Gives up after maxRetries and surfaces the last problem.
  m = mock([limited, limited, limited, limited]);
  await assert.rejects(new DidisClient({ fetch: m.fetchImpl }).health(), (e) => e instanceof DidisError && e.status === 429);
  assert.equal(m.calls.length, 3);

  // Disabled: one call only.
  m = mock([limited, { status: 200, body: {} }]);
  await assert.rejects(new DidisClient({ fetch: m.fetchImpl, retry: false }).health());
  assert.equal(m.calls.length, 1);

  // A wait longer than maxWaitMs is not slept through.
  m = mock([{ ...limited, headers: { ...limited.headers, "retry-after": "30" } }, { status: 200, body: {} }]);
  await assert.rejects(new DidisClient({ fetch: m.fetchImpl }).health());
  assert.equal(m.calls.length, 1);

  // Other errors are never retried.
  m = mock([{ status: 400, body: { title: "Bad", detail: "x" }, headers: { "retry-after": "0" } }, { status: 200, body: {} }]);
  await assert.rejects(new DidisClient({ fetch: m.fetchImpl }).health());
  assert.equal(m.calls.length, 1);
});

test("retryAfterMs reads delta-seconds and HTTP-dates", async () => {
  const { retryAfterMs } = await import("../dist/index.js");
  assert.equal(retryAfterMs("3"), 3000);
  assert.equal(retryAfterMs("Thu, 01 Jan 1970 00:00:10 GMT", 4000), 6000);
  assert.equal(retryAfterMs("soon"), null);
  assert.equal(retryAfterMs(undefined), null);
});

test("apiKey routes agent checks to the paid API with one idempotency key per call", async () => {
  const { calls, fetchImpl } = mock([]);
  const c = new DidisClient({ baseUrl: "http://x", fetch: fetchImpl, apiKey: "didis_test" });
  await c.inspectMcp("https://mcp.example.com/mcp");
  await c.inspectA2a("https://agent.example.com");
  await c.authorize(["r1"], "payments:transfer", { trustedRoots: ["did:web:a"] });
  await c.verifyDelegation(["r1"]);
  await c.usage();
  assert.deepEqual(calls.map((x) => `${x.init.method} ${x.url}`), [
    "POST http://x/v1/customer/mcp/inspect",
    "POST http://x/v1/customer/a2a/inspect",
    "POST http://x/v1/customer/agents/authorize",
    "POST http://x/v1/customer/agents/verify-delegation",
    "GET http://x/v1/customer/usage",
  ]);
  assert.deepEqual(JSON.parse(calls[0].init.body), { endpoint: "https://mcp.example.com/mcp" });
  assert.deepEqual(JSON.parse(calls[2].init.body), { chain: ["r1"], tool: "payments:transfer", trustedRoots: ["did:web:a"] });
  assert.deepEqual(JSON.parse(calls[3].init.body), { chain: ["r1"] });
  for (const x of calls) assert.equal(x.init.headers.authorization, "Bearer didis_test");
  const keys = calls.slice(0, 4).map((x) => x.init.headers["idempotency-key"]);
  assert.ok(keys.every((k) => /^[0-9a-f-]{36}$/.test(k)));
  assert.equal(new Set(keys).size, 4);
  assert.equal(calls[4].init.headers["idempotency-key"], undefined);
});

test("apiKey retry reuses the same idempotency key", async () => {
  const { calls, fetchImpl } = mock([{ status: 503, body: { title: "busy" }, headers: { "content-type": "application/problem+json", "retry-after": "0" } }, { status: 200, body: {} }]);
  await new DidisClient({ baseUrl: "http://x", fetch: fetchImpl, apiKey: "k" }).inspectMcp("https://m.example/mcp");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].init.headers["idempotency-key"], calls[1].init.headers["idempotency-key"]);
});

test("without apiKey nothing changes and no key is ever sent; register stays public", async () => {
  const { calls, fetchImpl } = mock([]);
  await new DidisClient({ baseUrl: "http://x", fetch: fetchImpl }).inspectMcp("https://m.example/mcp");
  const keyed = mock([]);
  await new DidisClient({ baseUrl: "http://x", fetch: keyed.fetchImpl, apiKey: "k" }).verifyDelegation(["r1"], { register: true });
  assert.equal(calls[0].url, "http://x/v1/mcp/inspect?endpoint=https%3A%2F%2Fm.example%2Fmcp");
  assert.equal(calls[0].init.headers.authorization, undefined);
  assert.equal(keyed.calls[0].url, "http://x/v1/agents/verify-delegation");
  assert.equal(keyed.calls[0].init.headers.authorization, undefined);
  await assert.rejects(new DidisClient({ baseUrl: "http://x", fetch: fetchImpl }).usage(), /apiKey is required/);
});
