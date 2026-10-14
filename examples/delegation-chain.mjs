// Register a delegation chain (root -> team -> agent) and ask which tools the agent may call.
//   node delegation-chain.mjs            # uses https://did.is/api
//   DIDIS_BASE_URL=... node delegation-chain.mjs
import { DidisClient } from "@didis/client";
import { newPrincipal, signReceipt } from "./_keys.mjs";

const didis = new DidisClient({ baseUrl: process.env.DIDIS_BASE_URL });

// 1. Three throwaway identities. In production the root is your organisation's DID.
const [root, team, agent] = await Promise.all([newPrincipal(), newPrincipal(), newPrincipal()]);

// 2. root grants the team weather + refunds; the team passes only weather on to the agent.
const r1 = await signReceipt(root, team, ["weather:*", "payments:refund"]);
const r2 = await signReceipt(team, agent, ["weather:*"], { parent: r1 });
const chain = [r1, r2]; // root first

// 3. Verify and register once. Only a VALID chain is registered.
const { result, registered } = await didis.verifyDelegation(chain, { trustedRoots: [root.did], register: true });
console.log(`chain: ${result.status} (${result.headline}), registered=${registered}`);
console.log(`effective capabilities: ${result.effectiveCapabilities.join(", ")}`);

// 4. From now on, ask by agent DID only (standard rate-limit budget).
for (const tool of ["weather:forecast", "weather:alerts:list", "payments:refund", "forecast"]) {
  const a = await didis.verifyTool(agent.did, tool, root.did);
  console.log(`${a.decision.padEnd(5)} ${tool.padEnd(20)} ${a.reason}`);
}
