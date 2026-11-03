// Compile-only regression: execution trust is required, advisory APIs remain rootless.
import { DidisClient, createDidisGuard, withDidisGuard, type DidisGuardOptions } from '../dist/index.js';
const client = new DidisClient();
const agent = 'did:key:zAgent';
const root = 'did:key:zTrusted';
createDidisGuard({ client, agent, root });
withDidisGuard(() => 1, { client, agent, root, tool: 'run' });
// @ts-expect-error: application trust must not be omitted
createDidisGuard({ client, agent });
// @ts-expect-error: undefined is not an execution root
createDidisGuard({ client, agent, root: undefined });
// @ts-expect-error: null is not an execution root
createDidisGuard({ client, agent, root: null });
// @ts-expect-error: one-line execution has the same required root
withDidisGuard(() => 1, { client, agent, tool: 'run' });
// @ts-expect-error: exported execution options require root
const rootless: DidisGuardOptions = { client, agent };
void rootless;
// Advisory inspection is intentionally unchanged; applications must not use its result as authority.
client.verifyTool(agent, 'run');
client.verifyDelegation([]);
client.authorize([], 'run');
