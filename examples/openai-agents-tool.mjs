// Guard OpenAI Agents SDK tools: the tool body runs only if DID.is says the agent was delegated
// the capability.
//   node openai-agents-tool.mjs
//
// No OpenAI API key is needed: the example invokes the tools the same way the Runner does
// (tool.invoke with the model's JSON arguments). Pass `tools` to `new Agent({ tools })` as usual.
//
// OpenAI function names allow only letters, digits, "_" and "-", so each tool maps to a DID.is
// capability: weather_forecast -> weather:forecast.
import { Agent, RunContext, tool } from "@openai/agents";
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
 * An Agents SDK tool whose `execute` runs only after the guard passes.
 * When the guard blocks, the model gets a short refusal instead of a result, so it can tell the
 * user rather than retry. Other errors go to the SDK's normal error handling.
 */
function guardedTool(execute, { name, capability, description, parameters }) {
  return tool({
    name, description, parameters,
    async execute(input, runContext) {
      try {
        await guard.check({ tool: name, capability });
      } catch (e) {
        if (e instanceof DidisGuardError) return `Blocked by policy (${e.code}). Do not retry this tool.`;
        throw e;
      }
      return execute(input, runContext);
    },
  });
}

const tools = [
  guardedTool(async ({ city }) => `Sunny in ${city}`, {
    name: "weather_forecast", capability: "weather:forecast",
    description: "Forecast for a city.", parameters: z.object({ city: z.string() }),
  }),
  guardedTool(async ({ order }) => `Refunded ${order}`, {
    name: "payments_refund", capability: "payments:refund",
    description: "Refund an order.", parameters: z.object({ order: z.string() }),
  }),
];
export const assistant = new Agent({ name: "Assistant", instructions: "Help with weather and orders.", tools });

// --- What the Runner does when the model picks a tool -------------------------------------------
const [forecast, refund] = tools;
const ctx = new RunContext();
console.log(`1. weather_forecast -> ${await forecast.invoke(ctx, JSON.stringify({ city: "Reykjavik" }))}`);
console.log(`2. payments_refund  -> ${await refund.invoke(ctx, JSON.stringify({ order: "A-1001" }))}`);
