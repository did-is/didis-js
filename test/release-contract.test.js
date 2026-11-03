import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { VERSION } from '../dist/index.js';
test('0.2.6 metadata and README disclose breaking root migration and bounded pins', () => {
 const read = name => readFileSync(new URL('../' + name, import.meta.url), 'utf8');
 assert.equal(VERSION, '0.2.6');
 assert.equal(JSON.parse(read('package.json')).version, VERSION);
 assert.match(read('CHANGELOG.md'), /## \[0\.2\.6\] - 2026-11-03/);
 assert.match(read('CHANGELOG.md'), /not a backward-compatible patch/);
 assert.match(read('README.md'), /TypeScript requires `root` statically; Python retains its Optional annotation/);
 assert.match(read('README.md'), /Missing\/null\/empty\/whitespace roots fail/);
 assert.match(read('README.md'), /Missing\/unparseable expiry retains TTL-only behavior/);
 assert.match(read('README.md'), /Missing completeness|missing completeness/);
 assert.match(read('README.md'), /requested reviewed pins only/);
 assert.doesNotMatch(read('README.md'), /Unreleased checkout migration|Package versions are unchanged/);
});
