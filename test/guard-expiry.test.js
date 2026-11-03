// Synthetic producer negatives: these are guard boundaries, not a core authorization bypass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDidisGuard, withDidisGuard, pinToolDefinitions } from '../dist/index.js';

const agent = 'did:key:zAgent';
const root = 'did:key:zRoot';
const definition = { name: 'tool', description: 'approved' };
const epoch = Date.parse('2030-01-01T00:00:00Z');
const iso = (ms) => new Date(ms).toISOString();
const allow = (extra = {}) => ({ agent, root, tool: 'cap:run', decision: 'ALLOW', authorized: true, reason: 'synthetic', ...extra });
const call = { tool: 'tool', capability: 'cap:run' };
const reject = (promise, code = 'TOOL_NOT_AUTHORIZED') => assert.rejects(promise, (e) => e.code === code);
async function clock(scenario) {
  const original = Date.now;
  let now = epoch;
  Date.now = () => now;
  try { await scenario((ms) => { now = epoch + ms; }); }
  finally { Date.now = original; }
}

for (const allowCacheMs of [0, 30_000]) {
  test(`fresh stale/equal ALLOW never executes, cache ${allowCacheMs}`, () => clock(async () => {
    for (const offset of [-1, 0]) {
      let checks = 0, effects = 0;
      const run = withDidisGuard(() => ++effects, {
        agent, root, ...call, allowCacheMs,
        client: { verifyTool: async () => { checks++; return allow({ expires: iso(epoch + offset) }); } },
      });
      await reject(run()); await reject(run());
      assert.equal(effects, 0); assert.equal(checks, 2);
    }
  }));
}

test('optional missing/null/malformed expiry retains TTL-only cache contract', () => clock(async (set) => {
  for (const extra of [{}, { expires: null }, { expires: '' }, { expires: 'not-a-date' }]) {
    set(0);
    let checks = 0;
    const guard = createDidisGuard({ agent, root, allowCacheMs: 100, client: { verifyTool: async () => { checks++; return allow(extra); } } });
    const run = guard.wrap(call, () => 'ok');
    assert.equal(await run(), 'ok'); set(99); assert.equal(await run(), 'ok'); assert.equal(checks, 1);
    set(100); assert.equal(await run(), 'ok'); assert.equal(checks, 2);
  }
}));

test('valid ALLOW is reused only within TTL AND expiry; refresh denial/stale/error never uses old ALLOW', () => clock(async (set) => {
  for (const refresh of ['deny', 'stale', 'error', 'valid']) {
    for (const ttl of [50, 500]) {
      set(0); let checks = 0, effects = 0;
      const client = { verifyTool: async () => {
        checks++;
        if (checks === 1) return allow({ expires: iso(epoch + 100) });
        if (refresh === 'error') throw new Error('offline');
        if (refresh === 'deny') return allow({ decision: 'DENY', authorized: false });
        return allow({ expires: iso(epoch + (refresh === 'stale' ? 100 : 1000)) });
      } };
      const run = createDidisGuard({ agent, root, client, allowCacheMs: ttl }).wrap(call, () => ++effects);
      await run(); set(49); await run(); assert.equal(checks, 1);
      set(100);
      if (refresh === 'valid') assert.equal(await run(), 3);
      else await reject(run(), refresh === 'error' ? 'GUARD_UNAVAILABLE' : 'TOOL_NOT_AUTHORIZED');
      assert.equal(checks, 2); assert.equal(effects, refresh === 'valid' ? 3 : 2);
      if (refresh !== 'valid') { await reject(run(), refresh === 'error' ? 'GUARD_UNAVAILABLE' : 'TOOL_NOT_AUTHORIZED'); assert.equal(checks, 3); }
    }
  }
}));

test('expiry elapsed while verifyTool awaited blocks first execution', () => clock(async (set) => {
  let effects = 0;
  const run = createDidisGuard({ agent, root, client: { verifyTool: async () => {
    const answer = allow({ expires: iso(epoch + 10) }); await Promise.resolve(); set(10); return answer;
  } } }).wrap(call, () => ++effects);
  await reject(run()); assert.equal(effects, 0);
}));

test('post-authorization pin refresh catches definition changes across the await', async () => {
  const pins = await pinToolDefinitions([definition]);
  let current = definition, effects = 0;
  const guard = createDidisGuard({ agent, root, pins, client: { verifyTool: async () => {
    await Promise.resolve(); current = { ...definition, description: 'changed during verify' }; return allow();
  } } });
  await reject(guard.wrap({ ...call, definition: () => current }, () => ++effects)(), 'TOOL_DRIFT');
  assert.equal(effects, 0);
});

test('fresh and cached deadlines are rechecked after asynchronous pin refresh', () => clock(async (set) => {
  const pins = await pinToolDefinitions([definition]);
  for (const cached of [false, true]) {
    set(0); let reads = 0, checks = 0, effects = 0;
    const guard = createDidisGuard({ agent, root, pins, client: { verifyTool: async () => { checks++; return allow({ expires: iso(epoch + 10) }); } } });
    if (cached) await guard.check({ ...call, definition });
    const run = guard.wrap({ ...call, definition: async () => {
      reads++; await Promise.resolve(); if (reads === 2) set(10); return definition;
    } }, () => ++effects);
    await reject(run()); assert.equal(effects, 0); assert.equal(checks, 1); assert.equal(reads, 2);
  }
}));

test('cache TTL elapsed during pin refresh cannot execute cached ALLOW', () => clock(async (set) => {
  const pins = await pinToolDefinitions([definition]);
  let reads = 0, effects = 0;
  const guard = createDidisGuard({ agent, root, pins, allowCacheMs: 10, client: { verifyTool: async () => allow({ expires: iso(epoch + 1000) }) } });
  await guard.check({ ...call, definition });
  const run = guard.wrap({ ...call, definition: async () => { if (++reads === 2) set(10); return definition; } }, () => ++effects);
  await reject(run()); assert.equal(effects, 0);
}));

test('pin+ALLOW async TOCTOU keeps each call snapshot despite a concurrent longer-lived refresh', () => clock(async (set) => {
  const pins = await pinToolDefinitions([definition]);
  let release, reached;
  const blocked = new Promise((resolve) => { reached = resolve; });
  const resume = new Promise((resolve) => { release = resolve; });
  let checks = 0, reads = 0, effects = 0;
  const guard = createDidisGuard({ agent, root, pins, allowCacheMs: 30_000, client: { verifyTool: async () => allow({ expires: iso(epoch + (++checks === 1 ? 10 : 1000)) }) } });
  const run = guard.wrap({ ...call, definition: async () => {
    if (++reads === 2) { reached(); await resume; } return definition;
  } }, () => ++effects);
  const pending = run();
  await blocked;
  set(10);
  await guard.check({ ...call, definition });
  release();
  await reject(pending);
  assert.equal(effects, 0); assert.equal(checks, 2);
}));

test('expiry in the final promise continuation is rejected immediately before handler invocation', () => clock(async (set) => {
  for (const useCheck of [false, true]) {
    set(0); let effects = 0;
    const guard = createDidisGuard({ agent, root, client: { verifyTool: async () => allow({ expires: iso(epoch + 10) }) },
      onDecision: (event) => {
        if (event.allowed) queueMicrotask(() => queueMicrotask(() => set(10)));
      },
    });
    await reject(useCheck ? guard.check(call) : guard.wrap(call, () => ++effects)());
    assert.equal(effects, 0);
  }
}));

for (const cached of [false, true]) {
  test(`pin changed during final async definition read refuses execution, cached ${cached}`, async () => {
    const pins = await pinToolDefinitions([definition]);
    let reads = 0, checks = 0, effects = 0;
    const guard = createDidisGuard({ agent, root, pins, requirePins: true, client: { verifyTool: async () => { checks++; return allow(); } } });
    if (cached) await guard.check({ ...call, definition });
    const run = guard.wrap({ ...call, definition: async () => {
      if (++reads === 2) pins.tool = '0'.repeat(64);
      await Promise.resolve();
      return definition;
    } }, () => ++effects);
    await reject(run(), 'TOOL_DRIFT');
    assert.equal(effects, 0); assert.equal(checks, 1);
  });
}

test('pin ticket refuses approval revocation while final definition resumes', async () => {
  const pins = await pinToolDefinitions([definition]);
  let reads = 0, effects = 0;
  const guard = createDidisGuard({ agent, root, pins, requirePins: true, client: { verifyTool: async () => allow() } });
  const run = guard.wrap({ ...call, definition: async () => {
    if (++reads === 2) queueMicrotask(() => { delete pins.tool; });
    return definition;
  } }, () => ++effects);
  await reject(run(), 'TOOL_DRIFT');
  assert.equal(effects, 0);
});
