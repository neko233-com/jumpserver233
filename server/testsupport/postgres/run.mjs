import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import {buildQAImage,isMissingDockerResource} from '../docker-qa.mjs';
const execute=promisify(execFile);
const port=Number(process.env.JMS_QA_POSTGRES_PORT||15441), health=Number(process.env.JMS_QA_POSTGRES_HEALTH_PORT||15442);
if(![port,health].every(p=>Number.isInteger(p)&&p>0&&p<65536))throw new Error('Invalid PostgreSQL QA ports');
const name=`jms233-postgres-${randomUUID()}`;
const root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid fixture owner');
const owner=root?basename(root):name;
if(root)writeFileSync(resolve(root,'postgres-container.json'),JSON.stringify({name,owner}));
if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,'jumpserver233-postgres-ci.json'),JSON.stringify({name,owner}));
let stopping=false;
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('PostgreSQL fixture ownership changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0);}catch{process.stderr.write('Owned PostgreSQL cleanup failed; retain resource record.\n');process.exit(1);}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
try{
 await buildQAImage(execute,['build','--tag','jms233-postgres-qa:local',fileURLToPath(new URL('.',import.meta.url))]);
 const args=['run','--detach','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--publish',`127.0.0.1:${port}:5432`,'--env','POSTGRES_USER=jumpserver','--env','POSTGRES_PASSWORD=synthetic-postgres-state-233','--env','POSTGRES_DB=jumpserver_test'];
 if(process.env.JMS_QA_POSTGRES_NETWORK){if(!/^[A-Za-z0-9_.-]+$/.test(process.env.JMS_QA_POSTGRES_NETWORK))throw new Error('Invalid network');args.push('--network',process.env.JMS_QA_POSTGRES_NETWORK);}
 args.push('jms233-postgres-qa:local');await execute('docker',args);
 let ready=false;for(let i=0;i<120;i++){try{await execute('docker',['exec',name,'psql','-U','jumpserver','-d','qa','-Atc','SELECT 1']);ready=true;break;}catch{await new Promise(r=>setTimeout(r,500));}}
 if(!ready)throw new Error('PostgreSQL did not become ready');
 const {stdout:ca}=await execute('docker',['exec',name,'cat','/run/qa-tls/server.crt']);
 const metadata={ready:true,address:`127.0.0.1:${port}`,network_address:`${name}:5432`,container_name:name,owner,root_ca_pem:ca,server_name:'postgres.synthetic.invalid',database:'qa',username:'qadb'};
 const server=createServer((req,res)=>{if(req.url!='/health'||req.method!=='GET'){res.writeHead(404).end();return;}res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(metadata));});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`PostgreSQL QA ready on 127.0.0.1:${port}; health ${health}\n`));
}catch(e){process.stderr.write(`PostgreSQL fixture startup failed: ${String(e.stderr||e.message).slice(-1200)}\n`);try{await cleanup();}catch{}process.exitCode=1;}
