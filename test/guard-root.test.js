import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDidisGuard, withDidisGuard, DidisGuardError } from '../dist/index.js';
const agent = 'did:key:zAgent', root = 'did:key:zTrusted';
const bad = (e) => e instanceof DidisGuardError && e.code === 'GUARD_MISCONFIGURED';
test('execution guard and one-line wrapper require an explicit application root before any work', () => {
  let network = 0, handlers = 0, definitions = 0;
  const client = { verifyTool: async () => { network++; return {}; } };
  for (const options of [{}, ...[undefined, null, '', ' ', '\t\n', 42, ' did:key:zTrusted', 'did:key:zTrusted '].map(root => ({ root }))]) {
    const config = { client, agent, ...options };
    assert.throws(() => createDidisGuard(config).wrap({ tool: 'run', definition: () => ++definitions }, () => ++handlers), bad);
    assert.throws(() => withDidisGuard(() => ++handlers, { ...config, tool: 'run' }), bad);
  }
  assert.deepEqual([network, handlers, definitions], [0, 0, 0]);
});
test('captured root is sent and compared even when config or response root changes', async () => {
  const seen = []; let effects = 0;
  const config = { agent, root, allowCacheMs: 0, client: { verifyTool: async (a, tool, r) => {
    seen.push(r); return { agent: a, tool, root: seen.length === 1 ? root : 'did:key:zAttacker', decision: 'ALLOW', authorized: true, reason: 'synthetic' };
  } } };
  const guard = createDidisGuard(config); config.root = 'did:key:zAttacker';
  const run = guard.wrap({ tool: 'run' }, () => ++effects);
  assert.equal(await run(), 1);
  await assert.rejects(run(), e => e.code === 'TOOL_NOT_AUTHORIZED');
  assert.deepEqual(seen, [root, root]); assert.equal(effects, 1);
});

test('TypeScript requires execution roots but retains rootless advisory API signatures', async () => {
  const { execFileSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  execFileSync(process.execPath, [
    fileURLToPath(new URL('../node_modules/typescript/bin/tsc', import.meta.url)),
    '--strict', '--noEmit', '--module', 'NodeNext', '--target', 'ES2022',
    fileURLToPath(new URL('./guard-root.types.ts', import.meta.url)),
  ], { stdio: 'pipe' });
});
