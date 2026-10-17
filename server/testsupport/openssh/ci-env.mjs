import { appendFileSync, readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import {isMissingDockerResource} from '../docker-qa.mjs'
const execute = promisify(execFile)
if (!process.env.RUNNER_TEMP) throw new Error('CI fixture requires RUNNER_TEMP')
const recordPath = resolve(process.env.RUNNER_TEMP, 'jumpserver233-keyhost-ci.json')
if (process.argv.includes('--cleanup')) {
  if (existsSync(recordPath)) {
    const resource = JSON.parse(readFileSync(recordPath, 'utf8'))
    if (!/^jms233-keyhost-[a-f0-9-]{36}$/.test(resource.name) || resource.owner !== resource.name) throw new Error('Invalid CI fixture owner')
    try {
      const { stdout } = await execute('docker', ['inspect', '--format', '{{json .Config.Labels}}', resource.name])
      if (JSON.parse(stdout)['com.jumpserver233.qa.owner'] !== resource.owner) throw new Error('CI fixture owner changed')
      await execute('docker', ['rm', '--force', resource.name])
    } catch (error) {
      if (!isMissingDockerResource(error)) throw error
    }
  }
} else {
  if (!process.env.GITHUB_ENV) throw new Error('CI environment output is unavailable')
  let metadata
  for (let attempt = 0; attempt < 300; attempt++) {
    try { const response = await fetch('http://127.0.0.1:12246/health', { signal: AbortSignal.timeout(1500) }); if (response.ok) { metadata = await response.json(); break } } catch { /* bounded startup */ }
    await new Promise((resolveWait) => setTimeout(resolveWait, 1000))
  }
  if (!metadata?.ready || !/^jms233-keyhost-[a-f0-9-]{36}$/.test(metadata.container_name) || !metadata.fingerprint?.startsWith('SHA256:')) throw new Error('Disposable CI OpenSSH fixture did not become ready')
  appendFileSync(process.env.GITHUB_ENV, `JMS_TEST_KEY_HOST_ADDR=${metadata.address}\nJMS_TEST_KEY_HOST_FINGERPRINT=${metadata.fingerprint}\nJMS_TEST_KEY_HOST_NAME=${metadata.container_name}\n`)
  if (metadata.protection) appendFileSync(process.env.GITHUB_ENV, 'JMS_TEST_KEY_HOST_PROTECTION=true\n')
  if (metadata.account_admin) appendFileSync(process.env.GITHUB_ENV, 'JMS_TEST_KEY_HOST_ACCOUNT_ADMIN=true\n')
}
