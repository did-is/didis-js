// Guard LangChain tools: the tool body runs only if DID.is says the agent was delegated the capability.
//   node langchain-tool.mjs
//
// No LLM or API key is needed: the example calls the tools the same way an agent loop would
// (tool.invoke with the model's arguments). Put `tools` into createAgent / bindTools as usual.
//
// LangChain tool names become function names for the model and cannot contain ":", so each
// tool maps to a DID.is capability: weather_forecast -> weather:forecast.
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { DidisClient, DidisGuardError, createDidisGuard } from "@didis/client";
import { newPrincipal, signReceipt } from "./_keys.mjs";

// --- Setup, done once outside the agent ---------------------------------------------------------
const didis = new DidisClient({ baseUrl: process.env.DIDIS_BASE_URL });
const [root, agent] = await Promise.all([newPrincipal(), newPrincipal()]);
// The agent may use weather:* only. Demo keys; real deployments issue receipts from their own keys.
await didis.verifyDelegation([await signReceipt(root, agent, ["weather:*"])], { trustedRoots: [root.did], register: true });

const guard = createDidisGuard({
  client: didis,
  agent: agent.did, // from configuration, never from model output
  root: root.did,
  onDecision: (d) => console.log(`  audit: ${d.allowed ? "ALLOW" : "BLOCK"} ${d.tool} (${d.capability}) ${d.code ?? ""}`),
});

/**
 * A LangChain tool whose body runs only after the guard passes.
 * When the guard blocks, the model gets a short refusal instead of a result, so it can tell the
 * user rather than retry. Other errors are thrown as usual.
 */
function guardedTool(fn, { name, capability, description, schema }) {
  return tool(async (input) => {
    try {
      await guard.check({ tool: name, capability });
    } catch (e) {
      if (e instanceof DidisGuardError) return `Blocked by policy (${e.code}). Do not retry this tool.`;
      throw e;
    }
    return fn(input);
  }, { name, description, schema });
}

const tools = [
  guardedTool(async ({ city }) => `Sunny in ${city}`, {
    name: "weather_forecast", capability: "weather:forecast",
    description: "Forecast for a city.", schema: z.object({ city: z.string() }),
  }),
  guardedTool(async ({ order }) => `Refunded ${order}`, {
    name: "payments_refund", capability: "payments:refund",
    description: "Refund an order.", schema: z.object({ order: z.string() }),
  }),
];
const [forecast, refund] = tools;

// --- What the agent loop does when the model picks a tool ---------------------------------------
console.log(`1. weather_forecast -> ${await forecast.invoke({ city: "Reykjavik" })}`);
console.log(`2. payments_refund  -> ${await refund.invoke({ order: "A-1001" })}`);
