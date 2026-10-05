# didis

Official TypeScript/JavaScript SDK for the [DID.is](https://did.is) public API: DID resolution with evidence, W3C DID Resolution, verifiable credentials, explicit policies, and MCP/A2A agent trust. Works anywhere `fetch` exists: Node 18+, Deno, Bun, browsers and edge runtimes. Zero dependencies, fully typed, ESM.

## Install

```bash
npm install didis
```

## Usage

```ts
import { DidisClient, DidisError } from "didis";

// Defaults to the public API at https://did.is/api.
// Self-hosting? new DidisClient({ baseUrl: "https://your-host/api" })
const didis = new DidisClient();

// Enriched resolution: verdict, evidence dimensions, graph, telemetry.
const r = await didis.resolve("did:web:identity.foundation");
console.log(r.verdict.headline);
for (const d of r.dimensions) console.log(d.label, d.state);

// DID Resolution v1 (W3C CR Draft HTTPS binding, unmodified).
const w3c = await didis.resolveW3c("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

// Live resolution stream (server-sent events).
for await (const ev of didis.stream("did:web:identity.foundation")) {
  if (ev.event === "stage") console.log(ev.data.label, ev.data.status);
  if (ev.event === "result") console.log(ev.data.verdict.outcome);
}

// Credentials: VC DM 2.0 / 1.1 with Data Integrity (eddsa-jcs-2022, ecdsa-jcs-2019) or VC-JOSE/VC-JWT.
// RDFC suites, ecdsa-sd-2023 and bbs-2023 are reported as UNSUPPORTED, never as valid.
const vc = await didis.verifyCredential(credential);
console.log(vc.status, vc.headline);

// Policies are explicit rules, never scores.
const { evaluation } = await didis.evaluatePolicy("did:web:example.com", {
  rules: { allowedMethods: ["web", "webvh"], domainBinding: "required", tlsMinDaysRemaining: 14 },
});

// Agents.
const mcp = await didis.inspectMcp("https://mcp.example.com/mcp");
const card = await didis.inspectA2a("https://agent.example.com");
const { authorization } = await didis.authorize(chain, "payments.refund", { trustedRoots: ["did:web:example.com"] });

try {
  await didis.resolve("did:web:does-not-exist.invalid");
} catch (e) {
  if (e instanceof DidisError) console.log(e.status, e.problem.code, e.problem.detail);
}
```

Identifiers are percent-encoded exactly once by the client. Non-2xx responses throw `DidisError` with the RFC 9457 problem body (including the resolution `trace` where available).

## Webhooks

Monitoring routes require an admin token (`new DidisClient({ adminToken })`) and must only be used server-side. Deliveries are signed:

```ts
import { verifyWebhookSignature } from "didis";

const ok = await verifyWebhookSignature(
  secret,
  req.headers["x-didis-timestamp"],
  rawBody,
  req.headers["x-didis-signature-256"],
);
```

## Surface

| Method | Route |
| --- | --- |
| `health()` | `GET /health` |
| `resolve(did, { noCache })` | `GET /v1/resolve/{did}` |
| `resolveW3c(did)` | `GET /1.0/identifiers/{did}` |
| `dereference(didUrl)` | `GET /v1/dereference/{didUrl}` |
| `stream(did)` | `GET /v1/stream/{did}` |
| `history(did)` / `diff(did, from?, to?)` / `graph(did)` | `GET /v1/history`, `/v1/diff`, `/v1/graph` |
| `verifyCredential(vc)` | `POST /v1/credentials/verify` |
| `evaluatePolicy(did, policy, vc?)` | `POST /v1/policies/evaluate` |
| `inspectMcp(endpoint)` / `inspectA2a(url)` | `GET /v1/mcp/inspect`, `/v1/a2a/inspect` |
| `verifyDelegation(chain, opts)` / `authorize(chain, tool, opts)` / `verifyTool(agent, tool, root?)` | `/v1/agents/*` |
| `fastVerifyDid(did)` / `fastVerifyJws(jws, relationship?)` | `/v1/fast-verify/*` |
| `watch` / `watches` / `unwatch` / `events` | `/v1/monitoring/*` (admin) |

Public API reference: <https://did.is/developers>. Monitoring routes (`watch`, `watches`, `unwatch`, `events`) need an admin token and are only available on self-hosted deployments; they are not exposed by the public API.

## License

MIT
