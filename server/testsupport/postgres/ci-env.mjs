import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import {isMissingDockerResource} from '../docker-qa.mjs';
if(!process.env.RUNNER_TEMP)throw new Error('RUNNER_TEMP required');
const record=resolve(process.env.RUNNER_TEMP,'jumpserver233-postgres-ci.json');
if(process.argv.includes('--cleanup')){
 if(existsSync(record)){const r=JSON.parse(readFileSync(record,'utf8'));if(!/^jms233-postgres-[a-f0-9-]{36}$/.test(r.name)||r.owner!==r.name)throw new Error('Invalid PostgreSQL fixture owner');try{const labels=JSON.parse(execFileSync('docker',['inspect','--format','{{json .Config.Labels}}',r.name],{encoding:'utf8',stdio:['ignore','pipe','pipe']}));if(labels['com.jumpserver233.qa.owner']!==r.owner)throw new Error('PostgreSQL owner changed');execFileSync('docker',['rm','--force','--volumes',r.name]);}catch(e){if(!isMissingDockerResource(e))throw e;}}
}else{
 if(!process.env.GITHUB_ENV)throw new Error('GITHUB_ENV required');let ready=false;for(let i=0;i<300;i++){try{const r=await fetch('http://127.0.0.1:15442/health',{signal:AbortSignal.timeout(1500)});if(r.ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,1000));}if(!ready)throw new Error('PostgreSQL fixture did not start');appendFileSync(process.env.GITHUB_ENV,'JMS_TEST_POSTGRES_FIXTURE_URL=http://127.0.0.1:15442/health\n');
}
