# @didis/client examples

Each example runs in a minute against the public API at `https://did.is/api`. No account or API key is needed.

```bash
cd examples
npm install
npm run delegation   # register a delegation chain, then ask which tools an agent may call
npm run guard        # guard tool handlers: allowed, not delegated, and definition drift
npm run webhook      # verify signed monitoring webhooks (self-test, no network)
npm run mcp          # guard every MCP tool call (MCP TypeScript SDK, in-memory server)
npm run langchain    # guard LangChain tools (no LLM or API key needed)
npm run openai-agents  # guard OpenAI Agents SDK tools (no OpenAI key needed)
```

The framework packages (`@modelcontextprotocol/sdk`, `@langchain/core`, `@openai/agents`, `zod`) are optional dependencies used only by those three examples.

Requires Node 20 or later (the examples sign with WebCrypto Ed25519; the SDK itself supports Node 18).
Set `DIDIS_BASE_URL` to use your own deployment.

| File | Shows |
| --- | --- |
| [`delegation-chain.mjs`](delegation-chain.mjs) | Build a root → team → agent chain, `verifyDelegation(..., { register: true })`, then `verifyTool`. Capabilities are namespace-scoped: `weather:*` grants `weather:forecast`, not `forecast` or `payments:refund`. |
| [`guard-tool.mjs`](guard-tool.mjs) | `pinToolDefinitions` + `createDidisGuard`. The refund tool is blocked (`TOOL_NOT_AUTHORIZED`); the forecast tool is blocked after its description changes (`TOOL_DRIFT`). |
| [`mcp-client.mjs`](mcp-client.mjs) | One `callTool` function for every MCP call: maps the MCP tool name to a capability (`weather_forecast` → `weather:forecast`), checks the definition the server serves *now* against the pin, then asks DID.is. Shows allowed, not delegated, and a server that changes a description. |
| [`langchain-tool.mjs`](langchain-tool.mjs) | `guardedTool(...)` wraps a LangChain `tool()`. A blocked call returns a short refusal to the model instead of running. |
| [`openai-agents-tool.mjs`](openai-agents-tool.mjs) | The same for an OpenAI Agents SDK `tool()` and `new Agent({ tools })`. |
| [`webhook-receiver.mjs`](webhook-receiver.mjs) | `verifyCustomerMonitorSignature` on the raw body, duplicate handling, and `401` for forged or altered requests. |
| [`_keys.mjs`](_keys.mjs) | Demo-only throwaway `did:key` identities and signed delegation receipts. |

**Why a separate capability?** MCP and OpenAI tool names may only contain letters, digits, `_`, `-` and `.`, so they cannot be `weather:forecast`. DID.is capabilities use `:` namespaces so that `weather:*` can grant a whole group. Give the guard both: `{ tool: "weather_forecast", capability: "weather:forecast" }`. Pins use the tool name; DID.is is asked about the capability.

The demo keys exist only in memory. Registered demo chains expire after an hour.

Docs: [Guard agent tools](https://docs.did.is/build/guard-tools/) · [Agent trust APIs](https://docs.did.is/build/agents/) · [Webhook signatures](https://docs.did.is/build/webhooks/)
