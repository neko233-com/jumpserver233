import {appendFileSync,existsSync,readFileSync,rmSync} from 'node:fs';
import {resolve,dirname,basename} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {isMissingDockerResource} from '../docker-qa.mjs';
if(!process.env.RUNNER_TEMP)throw new Error('RUNNER_TEMP required');
for(const engine of ['mysql','mariadb','sqlserver','clickhouse','redis','mongodb','kubernetes','telnet','rdp','radius']){
 const record=resolve(process.env.RUNNER_TEMP,`jumpserver233-${engine}-ci.json`);
 if(process.argv.includes('--cleanup')){
  if(!existsSync(record))continue;const r=JSON.parse(readFileSync(record,'utf8'));if(!new RegExp(`^jms233-${engine}-[a-f0-9-]{36}$`).test(r.name)||r.owner!==r.name)throw new Error('Invalid SQL fixture owner');
  try{const labels=JSON.parse(execFileSync('docker',['inspect','--format','{{json .Config.Labels}}',r.name],{encoding:'utf8',stdio:['ignore','pipe','pipe']}));if(labels['com.jumpserver233.qa.owner']!==r.owner)throw new Error('SQL owner changed');execFileSync('docker',['rm','--force','--volumes',r.name]);}catch(e){if(!isMissingDockerResource(e))throw e;}
  if(r.cert_directory){const p=resolve(r.cert_directory);if(dirname(p).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(p).startsWith(`jms233-${engine}-cert-`))throw new Error('Invalid SQL certificate cleanup path');rmSync(p,{recursive:true,force:true});}
 }else{
  if(!process.env.GITHUB_ENV)throw new Error('GITHUB_ENV required');const url=`http://127.0.0.1:${engine==='mysql'?15462:engine==='mariadb'?15464:engine==='sqlserver'?15472:engine==='clickhouse'?15482:engine==='redis'?15492:engine==='kubernetes'?16444:engine==='telnet'?16524:engine==='rdp'?19390:engine==='radius'?18514:15502}/health`;let ready=false;for(let i=0;i<300;i++){try{const r=await fetch(url,{signal:AbortSignal.timeout(1500)});if(r.ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,1000));}if(!ready)throw new Error(`${engine} fixture did not start`);appendFileSync(process.env.GITHUB_ENV,`JMS_TEST_${engine.toUpperCase()}_FIXTURE_URL=${url}\n`);
 }
}
