import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fixtureGroups, fixturesFor, fixtureCommand} from './ci-fixtures.mjs';

test('CI shards cover all ten external engines once, with K3s isolated from databases', () => {
  const engines = Object.values(fixtureGroups).flat();
  assert.equal(new Set(engines).size, 10);
  assert.deepEqual([...engines].sort(), ['mysql','mariadb','sqlserver','clickhouse','redis','mongodb','kubernetes','telnet','rdp','radius'].sort());
  assert.deepEqual(fixturesFor('access'), ['kubernetes','telnet','rdp','radius']);
  const copy = fixturesFor('access'); copy.pop();
  assert.equal(fixturesFor('access').length, 4);
  for (const invalid of ['', 'all', '__proto__', 'constructor']) assert.throws(() => fixturesFor(invalid));
});
test('fixture dispatch uses fixed scripts, private loopback ports and known engine selectors', () => {
  for (const engine of Object.values(fixtureGroups).flat()) {
    const c = fixtureCommand(engine);
    assert.match(c.script, /^server\/testsupport\/[a-z]+\/run\.mjs$/);
    assert.match(c.url, /^http:\/\/127\.0\.0\.1:\d+\/health$/);
  }
  assert.deepEqual(fixtureCommand('mariadb').env, {JMS_QA_SQL_ENGINE:'mariadb'});
  assert.deepEqual(fixtureCommand('mongodb').env, {JMS_QA_NOSQL_ENGINE:'mongodb'});
  assert.throws(() => fixtureCommand('../foreign'));
});
test('only generated release metadata skips duplicate runtime suites', () => {
  const ci = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  const exclusions = [...ci.matchAll(/paths-ignore: \[(.*?)\]/g)].map(m => m[1]);
  assert.deepEqual(exclusions, Array(2).fill("'CHANGELOG.md', '.release-please-manifest.json'"));
});
test('all shards are mandatory, bounded, and clean only owned fixture records', () => {
  const ci = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  assert.match(ci, /external-integrations:[\s\S]*?fail-fast: false/);
  for (const group of Object.keys(fixtureGroups)) assert(ci.includes(`group: ${group}`));
  const shard = ci.slice(ci.indexOf('  external-integrations:'), ci.indexOf('  frontend:'));
  assert(!shard.includes('continue-on-error'));
  assert.match(shard, /timeout-minutes: 30/);
  assert.match(shard, /if: always\(\)[\s\S]*?mysql\/ci-env\.mjs --cleanup/);
  assert.match(shard, /go test -count=1/);
  assert.match(shard, /Start external integration OpenSSH gateway[\s\S]*?openssh\/ci-env\.mjs/);
  assert.match(shard, /Clean external integration OpenSSH gateway\n\s+if: always\(\)/);
  assert.match(ci, /external_only:\n\s+type: boolean\n\s+default: false/);
  // Normal pushes/PRs always keep every gate. A scheduling-only follow-up can
  // run alongside the unchanged full suite instead of cancelling it.
  assert.match(ci, /backend_only:\n\s+type: boolean\n\s+default: false/);
  assert.match(ci, /inputs.external_only && !inputs.backend_only/);
  assert.equal((ci.match(/inputs.external_only \|\| inputs.backend_only/g)||[]).length, 2);
  assert.match(ci, /go test -count=3 -timeout 20m -p 1 \.\/internal\/core\/operations \.\/internal\/api/);
});

test('native browser repair is explicit and cannot narrow ordinary CI', () => {
 const ci=readFileSync(new URL('../.github/workflows/ci.yml',import.meta.url),'utf8').replaceAll('\r\n','\n');
 assert.match(ci,/frontend_only:\n\s+type: boolean\n\s+default: false/);
 assert.match(ci,/JMS_E2E_NATIVE_AUDIT_ONLY: \$\{\{ github.event_name == 'workflow_dispatch' && inputs.frontend_only && 'true' \|\| 'false' \}\}/);
 const config=readFileSync(new URL('../web/playwright.config.ts',import.meta.url),'utf8');
 assert.match(config,/JMS_E2E_NATIVE_AUDIT_ONLY === "true" \? \/renders native SFTP rename audit\/ : undefined/);
});
