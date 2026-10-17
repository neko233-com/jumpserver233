import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createServer } from 'node:http'
import { createConnection } from 'node:net'
import { randomUUID } from 'node:crypto'
import { basename, resolve, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {buildQAImage,isMissingDockerResource} from '../docker-qa.mjs'

const execute = promisify(execFile)
const directory = fileURLToPath(new URL('.', import.meta.url))
const sshPort = Number(process.env.JMS_QA_KEYHOST_SSH_PORT || '12241')
const httpPort = Number(process.env.JMS_QA_KEYHOST_HTTP_PORT || '12242')
if (![sshPort, httpPort].every((port) => Number.isInteger(port) && port > 0 && port < 65536)) throw new Error('Invalid QA key-host port')
const name = `jms233-keyhost-${randomUUID()}`
const testRoot = process.env.JMS_E2E_DATA_DIR ? resolve(process.env.JMS_E2E_DATA_DIR) : null
const owner = testRoot ? basename(testRoot) : name
if (testRoot && (dirname(testRoot).toLowerCase() !== resolve(tmpdir()).toLowerCase() || !basename(testRoot).startsWith('jumpserver233-e2e-'))) throw new Error('Refusing unowned E2E resource record')
if (testRoot) writeFileSync(resolve(testRoot, 'openssh-container.json'), JSON.stringify({ name, owner }))
if (process.env.RUNNER_TEMP && !testRoot) writeFileSync(resolve(process.env.RUNNER_TEMP, 'jumpserver233-keyhost-ci.json'), JSON.stringify({ name, owner }))
let stopping = false
async function cleanup() {
  try {
    const { stdout } = await execute('docker', ['inspect', '--format', '{{json .Config.Labels}}', name])
    if (JSON.parse(stdout)['com.jumpserver233.qa.owner'] !== owner) throw new Error('OpenSSH fixture ownership changed')
    await execute('docker', ['rm', '--force', name])
  } catch (error) {
    if (!isMissingDockerResource(error)) throw error
  }
}
async function stop() {
  if (stopping) return
  stopping = true
  try { await cleanup(); process.exit(0) } catch { process.stderr.write('Could not clean the owned OpenSSH fixture; retain its resource record.\n'); process.exit(1) }
}
process.on('SIGINT', () => { void stop() })
process.on('SIGTERM', () => { void stop() })
function reachable() { return new Promise((resolveResult) => { const socket = createConnection({ host: '127.0.0.1', port: sshPort }); const finish = (ok) => { socket.destroy(); resolveResult(ok) }; socket.setTimeout(1000, () => finish(false)); socket.once('connect', () => finish(true)); socket.once('error', () => finish(false)) }) }
try {
  process.stdout.write('Building disposable OpenSSH QA image…\n')
  await buildQAImage(execute, ['build', '--tag', 'jms233-openssh-qa:local', directory])
  const argumentsList = ['run', '--detach', '--name', name, '--label', `com.jumpserver233.qa.owner=${owner}`, '--publish', `127.0.0.1:${sshPort}:22`]
  const protection = process.env.JMS_QA_KEYHOST_PROTECTION === 'true'
  const accountAdmin = process.env.JMS_QA_KEYHOST_ACCOUNT_ADMIN === 'true'
  if (accountAdmin) argumentsList.push('--env','JMS_QA_ACCOUNT_ADMIN=true')
  if (protection) argumentsList.push('--cap-add','NET_ADMIN','--env','JMS_QA_PROTECTION=true')
  const network = process.env.JMS_QA_KEYHOST_NETWORK
  if (network) { if (!/^[A-Za-z0-9_.-]+$/.test(network)) throw new Error('Invalid QA network'); argumentsList.push('--network', network) }
  argumentsList.push('jms233-openssh-qa:local')
  await execute('docker', argumentsList)
  let fingerprint = ''
  for (let attempt = 0; attempt < 60; attempt++) {
    try { const { stdout } = await execute('docker', ['exec', name, 'ssh-keygen', '-l', '-E', 'sha256', '-f', '/run/keyhost-ed25519.pub']); fingerprint = stdout.trim().split(/\s+/)[1]; if (fingerprint?.startsWith('SHA256:') && await reachable()) break } catch { /* Startup is bounded below. */ }
    await new Promise((resolveWait) => setTimeout(resolveWait, 500))
  }
  if (!fingerprint?.startsWith('SHA256:') || !await reachable()) throw new Error('OpenSSH fixture did not become ready')
  const server = createServer(async (request, response) => {
    if (request.method !== 'GET' || request.url !== '/health') { response.writeHead(404).end(); return }
    const ready = await reachable()
    response.writeHead(ready ? 200 : 503, { 'Content-Type': 'application/json' })
    response.end(JSON.stringify({ ready, protection, account_admin: accountAdmin, address: `127.0.0.1:${sshPort}`, network_address: `${name}:22`, username: 'keyqa', fingerprint, container_name: name, owner }))
  })
  server.on('error', async () => { await cleanup(); process.exit(1) })
  server.listen(httpPort, '127.0.0.1', () => { process.stdout.write(`OpenSSH QA ready on 127.0.0.1:${sshPort}; health ${httpPort}\n`) })
} catch (error) {
  process.stderr.write(`OpenSSH fixture startup failed: ${String(error.stderr || error.message).slice(-1200)}\n`)
  try { await cleanup() } catch { process.stderr.write('Owned OpenSSH fixture cleanup needs attention.\n') }
  process.exitCode = 1
}
