# Changelog

All notable changes to `@didis/client` are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the package uses [Semantic Versioning](https://semver.org/). Before 1.0.0, a minor version (0.x.0) may add features; breaking changes are called out under **Changed** with a migration note.

## [Unreleased]

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

[Unreleased]: https://github.com/did-is/didis-js/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/did-is/didis-js/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/did-is/didis-js/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/did-is/didis-js/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/did-is/didis-js/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/did-is/didis-js/releases/tag/v0.1.0
