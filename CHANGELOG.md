# Changelog

All notable changes to `@didis/client` are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and release numbering follows the project’s pre-1.0 policy. A third-component increment can contain breaking changes; read **Changed** and migration notes before upgrading. 0.2.6 is not a backward-compatible patch.

## [Unreleased]

## [0.2.7] - 2026-11-03

### Fixed

- Correct first-party license attribution to DID.is; MIT permission and disclaimer terms are unchanged.

### Migration

- This release includes the execution-guard hardening and response types described under 0.2.6 below. **Upgrading from 0.2.5 is not a backward-compatible patch:** configure an application-owned trusted root for every guard; TypeScript requires `root` statically and Python enforces it at runtime with `GUARD_MISCONFIGURED`. Never derive the trusted root from submitted chains or model output. Expired approval, awaited-definition and immutable-deadline checks remain enforced; definition pins do not authorize callers or guarantee tool behavior.
- npm 0.2.6 was not published. 0.2.7 is the first npm release after 0.2.5 to deliver these changes; the 0.2.6 entry documents the earlier source release.

## [0.2.6] - 2026-11-03

### Fixed

- `createDidisGuard` / `withDidisGuard`: reject an ALLOW whose parseable `expires` is at or before execution time with the existing `TOOL_NOT_AUTHORIZED` code, including first use and disabled caching. Re-read pinned definitions after authorization and recheck each call's immutable deadline after async work and immediately before handler invocation; concurrent refreshes cannot extend another call's approval. Cached ALLOW is still bounded by both configured TTL and delegation expiry; failed/DENY/expired refreshes never fall back to stale approval (`GUARD_UNAVAILABLE` for transport/unexpected-answer errors). Missing/unparseable expiry remains optional and keeps the existing TTL-only behavior. Pin providers may now run twice per check. Each call retains the checked approval pin and synchronously compares it with the current pin immediately before execution; changes during asynchronous definition reads fail with `TOOL_DRIFT`. This is a pre-execution boundary, not per-stream reauthorization, resource binding, replay prevention, or an atomic remote side-effect guarantee.

### Changed

- **Breaking in 0.2.6:** execution guards require a nonempty, trimmed application-owned trusted root DID. Missing/null/empty/whitespace roots raise `GUARD_MISCONFIGURED` at construction, before network or handler work. Migrate every guard and one-line wrapper by passing the root from trusted application configuration, not from a submitted chain, authorization response, or model output. Rootless advisory verification APIs remain available; signature-valid does not mean application-authorized. 0.2.5 accepts rootless guards; 0.2.6 rejects them. TypeScript requires `root` statically; Python retains its Optional annotation but enforces it at runtime.

- Correct delegation response fields to required nullable wire values; correct fast-verification explicit null fields. Wire-type corrections only; these corrections do not alter HTTP routing.

### Added

- Add optional tools-only inventory completeness/evidence (missing means unknown); scoped requested-pin attestation preserves partial-result pin checks and rejects duplicate ambiguity. Missing completeness remains unknown, not complete.

- `diffObservations()` selects exact public history observations, including domain-only changes with identical document hashes. Semantic diff adds optional `fromObservation`/`toObservation` references. Legacy hash selectors remain available but ambiguous hashes return `INVALID_REQUEST` instead of silently selecting a different state. No change to private usage/billing routes.

## [0.2.5] - 2026-10-19

### Added

- Optional project API key: `new DidisClient({ apiKey })`. With a key, MCP inspection, A2A inspection, tool-call authorization and delegation-chain checks use the paid `/v1/customer/*` routes and count against your team's monthly allowance instead of the anonymous per-IP limit. Results are identical to the public routes. Each call sends one fresh `Idempotency-Key`; automatic `429`/`503` retries reuse it, so a request is never billed twice. The key is never sent to public routes, and `register: true` delegation checks always use the public route. Without a key nothing changes.
- `usage()` returns this month's team allowance (`CustomerUsage`: used, reserved, limit and remaining per pool). Requires the API key.

## [0.2.4] - 2026-10-19

### Added

- Automatic wait-and-retry for `429` (request budget used up) and `503` (temporarily overloaded) responses that carry `Retry-After`. By default the client retries up to 2 times and never waits longer than 10 seconds per attempt; a short random delay is added so clients refused together do not return together. Both statuses are refused before the request is processed, so retrying is safe for every call. Tune with `new DidisClient({ retry: { maxRetries, maxWaitMs } })` or turn off with `retry: false`. When retries run out, the last `DidisError` is thrown as before, with `problem.retryAfter`.

## [0.2.3] - 2026-10-18

### Added

- Requests now carry `user-agent: didis-client/<version>` (Node, Deno, Bun and other non-browser runtimes; browsers keep their own user agent). Only the package name and version are sent, so DID.is can count SDK use separately from other HTTP clients. New export `VERSION`.

- Type `LinkedAccountEvidence` and `Evidence.linkedAccounts`: each `alsoKnownAs` value with whether that website links back to the DID (`CONFIRMED`, `NOT_CONFIRMED`, `FAILED`, `UNSUPPORTED`, `UNREACHABLE`, `NOT_CHECKABLE`). A confirmation proves the same party controls the website origin and the DID; it does not prove who that party is.

- Policy rule `linkedAccounts` in `PolicyRules`: 1–4 https origins (for example `["https://shop.example"]`) that must be listed in the DID's `alsoKnownAs` and confirm the DID back. Use it to require "this DID belongs to our official website" in one policy call.

## [0.2.2] - 2026-10-18

### Added

- `verifyCredential` option `requiredClaims` (`ClaimRequirement[]`): check conditions such as `{ path: "/age_over_18", equals: true }` without receiving claim values. The response field `requirements` (`RequirementsOutcome`) reports `met` and a per-path result; conditions are evaluated only for a `VALID` credential.

## [0.2.1] - 2026-10-14

### Added

- Guard option `capability` (on `check`, `wrap` and `withDidisGuard`): the DID.is capability a tool needs when it differs from the tool name. MCP and OpenAI tool names cannot contain `:`, so use `{ tool: "weather_forecast", capability: "weather:forecast" }`. Pins stay keyed by the tool name; DID.is is asked about the capability; the ALLOW cache is keyed by capability. Without `capability`, behaviour is unchanged (the tool name is the capability).
- `onDecision` events and `DidisGuardError.detail` now include `capability`.
- Examples for the MCP TypeScript SDK (`mcp-client.mjs`), LangChain (`langchain-tool.mjs`) and the OpenAI Agents SDK (`openai-agents-tool.mjs`).

### Changed

- A capability containing `*`, empty segments or whitespace is refused with `GUARD_MISCONFIGURED` before any network call. Wildcards belong in delegations, not in tool calls.

## [0.2.0] - 2026-10-13

### Added

- Fail-closed tool guard: `createDidisGuard`, `withDidisGuard` and `DidisGuardError`. A guarded handler runs only when the tool definition still matches its pin and DID.is `verifyTool` answers `ALLOW` for the configured agent (and root, if set). Drift, `DENY`, network errors, `429` and unexpected answers all throw, and the handler does not run. See [Guard agent tools](https://docs.did.is/build/guard-tools/).
- Tool definition pinning: `canonicalJson` (RFC 8785 JCS), `toolDefinitionSha256`, `mcpInventoryHash` and `pinToolDefinitions`. Hashes are identical to the `definitionSha256` and `inventoryHash` values DID.is reports.
- `attestMcpPins(client, endpoint, pins)` compares a public MCP server, as observed by DID.is, with your pins.
- `verifyCredential` options `expectedNonce` and `trustedIssuerCertificates` (SD-JWT VC key binding and caller-chosen X.509 anchors), with the `CredentialVerifyOptions` type.
- Response types `IssuerTrust` and `SdJwtEvidence`, and the optional `issuerTrust` and `sdJwt` fields on `CredentialVerification`.

### Fixed

- Node 18: WebCrypto is loaded from `node:crypto` when there is no global `crypto`. Before this, `verifyWebhookSignature` and `verifyCustomerMonitorSignature` failed on Node 18 with `crypto is not defined`.

## [0.1.0] - 2026-10-05

### Added

- First public release as `@didis/client`. Zero dependencies, ESM, Node 18+, Deno, Bun, browsers and edge runtimes.
- `DidisClient` for the DID.is public API (default base URL `https://did.is/api`): `health`, `resolve`, `resolveW3c`, `dereference`, `stream` (server-sent events), `history`, `diff`, `graph`, `verifyCredential`, `evaluatePolicy`, `inspectMcp`, `inspectA2a`, `verifyDelegation`, `authorize`, `verifyTool`, `fastVerifyDid` and `fastVerifyJws`.
- Self-hosted monitoring methods that need an admin token: `watch`, `watches`, `unwatch` and `events`.
- `DidisError` carrying the RFC 9457 problem body and `Retry-After`.
- Webhook helpers `verifyWebhookSignature` and `verifyCustomerMonitorSignature`.

[Unreleased]: https://github.com/did-is/didis-js/compare/v0.2.7...HEAD
[0.2.6]: https://github.com/did-is/didis-js/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/did-is/didis-js/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/did-is/didis-js/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/did-is/didis-js/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/did-is/didis-js/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/did-is/didis-js/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/did-is/didis-js/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/did-is/didis-js/releases/tag/v0.1.0

[0.2.7]: https://github.com/did-is/didis-js/compare/v0.2.6...v0.2.7
