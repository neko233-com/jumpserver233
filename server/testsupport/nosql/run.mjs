import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {randomUUID} from 'node:crypto';
import {writeFileSync,readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {basename,dirname,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {isMissingDockerResource} from '../docker-qa.mjs';
const engine=process.env.JMS_QA_NOSQL_ENGINE||'redis';if(!['redis','mongodb'].includes(engine))throw new Error('Unsupported NoSQL fixture');
const prefix=`JMS_QA_${engine.toUpperCase()}`,internal=engine==='redis'?6379:27017;
const port=Number(process.env[`${prefix}_PORT`]||(engine==='redis'?15491:15501)),health=Number(process.env[`${prefix}_HEALTH_PORT`]||(engine==='redis'?15492:15502));
if(![port,health].every(p=>Number.isInteger(p)&&p>0&&p<65536))throw new Error('Invalid NoSQL QA ports');
const execute=promisify(execFile),directory=fileURLToPath(new URL('.',import.meta.url));
const name=`jms233-${engine}-${randomUUID()}`,root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid QA owner');
const owner=root?basename(root):name,certDir=mkdtempSync(resolve(tmpdir(),`jms233-${engine}-cert-`));let stopping=false;
const record={name,owner,cert_directory:certDir};if(root)writeFileSync(resolve(root,`${engine}-container.json`),JSON.stringify(record));if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,`jumpserver233-${engine}-ci.json`),JSON.stringify(record));
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('NoSQL fixture owner changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}const p=resolve(certDir);if(dirname(p).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(p).startsWith(`jms233-${engine}-cert-`))throw new Error('Invalid certificate path');rmSync(p,{recursive:true,force:true});}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0);}catch{process.stderr.write('NoSQL cleanup failed; preserve owner record.\n');process.exit(1);}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
try{
 await execute('go',['run','./testsupport/mysql/cert',certDir],{cwd:resolve(directory,'../..')});
 const probe=resolve(certDir,process.platform==='win32'?'probe.exe':'probe');await execute('go',['build','-o',probe,'./testsupport/nosql/probe'],{cwd:resolve(directory,'../..')});
 const args=['run','--detach','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--publish',`127.0.0.1:${port}:${internal}`,'--user','0','--mount',`type=bind,source=${certDir},target=/qa-input,readonly`,'--mount',`type=bind,source=${resolve(directory,`${engine}.sh`)},target=/qa-start.sh,readonly`,'--entrypoint','sh'];
 const network=process.env[`${prefix}_NETWORK`];if(network){if(!/^[A-Za-z0-9_.-]+$/.test(network))throw new Error('Invalid QA network');args.push('--network',network);}
 if(engine==='mongodb')args.push('--env','MONGO_INITDB_ROOT_USERNAME=qadb','--env','MONGO_INITDB_ROOT_PASSWORD=synthetic-mongodb-query-233');
 args.push(engine==='redis'?'redis:8.2-alpine':'mongo:8.0','/qa-start.sh');await execute('docker',args);
 let ready=false;for(let i=0;i<120;i++){try{await execute(probe,[engine,`127.0.0.1:${port}`,resolve(certDir,'server.crt')],{timeout:4000});ready=true;break;}catch{if(i%5===0){const state=await execute('docker',['inspect','--format','{{.State.Running}}',name]);if(state.stdout.trim()!=='true')break;}await new Promise(r=>setTimeout(r,500));}}
 if(!ready)throw new Error('NoSQL database did not become ready');
 const metadata={ready:true,protocol:engine,address:`127.0.0.1:${port}`,network_address:`${name}:${internal}`,container_name:name,owner,root_ca_pem:readFileSync(resolve(certDir,'server.crt'),'utf8'),server_name:`${engine}.synthetic.invalid`,database:engine==='redis'?'0':'qa',auth_database:engine==='mongodb'?'admin':'',username:'qadb'};
 const server=createServer((req,res)=>{if(req.url!='/health'||req.method!=='GET'){res.writeHead(404).end();return;}res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(metadata));});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`${engine} TLS QA ready on 127.0.0.1:${port}; health ${health}\n`));
}catch(e){process.stderr.write(`NoSQL startup failed: ${String(e.stderr||e.message).slice(-1500)}\n`);try{const logs=await execute('docker',['logs','--tail','100',name]);const output=logs.stderr+logs.stdout;const failures=output.split(/\r?\n/).filter(line=>{try{return ['E','F'].includes(JSON.parse(line).s);}catch{return false;}});process.stderr.write((failures.join('\n')+'\n'+output.slice(-2500)).slice(-8000));}catch{}try{await cleanup();}catch{}process.exitCode=1;}
