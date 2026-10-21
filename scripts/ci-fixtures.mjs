import {spawn} from 'node:child_process';
import {openSync, closeSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {waitCIHealth} from '../server/testsupport/ci-health.mjs';

// Separate memory-heavy services onto distinct hosted runners. Start each
// fixture once and await readiness before preparing the next one.
export const fixtureGroups = Object.freeze({
  relational: ['mysql', 'mariadb', 'sqlserver'],
  data: ['clickhouse', 'redis', 'mongodb'],
  access: ['kubernetes', 'telnet', 'rdp', 'radius'],
});
const ports = {mysql:15462, mariadb:15464, sqlserver:15472, clickhouse:15482,
  redis:15492, mongodb:15502, kubernetes:16444, telnet:16524, rdp:19390, radius:18514};
export function fixturesFor(group) {
  if (!Object.hasOwn(fixtureGroups, group)) throw new Error('Unknown CI fixture group');
  return [...fixtureGroups[group]];
}
export function fixtureCommand(engine) {
  if (!Object.hasOwn(ports, engine)) throw new Error('Unknown CI fixture');
  const env = engine === 'mysql' || engine === 'mariadb' ? {JMS_QA_SQL_ENGINE:engine}
    : engine === 'redis' || engine === 'mongodb' ? {JMS_QA_NOSQL_ENGINE:engine} : {};
  const directory = engine === 'mariadb' ? 'mysql' : engine === 'redis' || engine === 'mongodb' ? 'nosql' : engine;
  return {script:`server/testsupport/${directory}/run.mjs`, env,
    url:`http://127.0.0.1:${ports[engine]}/health`,
    logName:['telnet', 'rdp', 'radius'].includes(engine) ? engine : `${engine}-query`};
}
export async function startGroup(group) {
  const engines = fixturesFor(group);
  if (!process.env.RUNNER_TEMP || !process.env.GITHUB_ENV) throw new Error('CI paths required');
  for (const engine of engines) {
    const command = fixtureCommand(engine);
    const logPath = resolve(process.env.RUNNER_TEMP, `${command.logName}.log`);
    const fd = openSync(logPath, 'w', 0o600);
    let child;
    try {
      child = spawn(process.execPath, [command.script], {
        env:{...process.env, ...command.env}, detached:true, stdio:['ignore', fd, fd],
      });
      await new Promise((ok, fail) => {child.once('spawn', ok); child.once('error', fail);});
    } finally {closeSync(fd);}
    child.unref();
    const pidPath = resolve(process.env.RUNNER_TEMP, `${engine}.pid`);
    writeFileSync(pidPath, String(child.pid), {mode:0o600});
    await waitCIHealth({engine, url:command.url, pidPath, logPath});
    // Only a loopback health endpoint is exported; fixture credentials stay private.
    const {appendFileSync} = await import('node:fs');
    appendFileSync(process.env.GITHUB_ENV, `JMS_TEST_${engine.toUpperCase()}_FIXTURE_URL=${command.url}\n`);
    process.stdout.write(`${engine} fixture ready\n`);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await startGroup(process.argv[2]);
}
