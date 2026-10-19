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
