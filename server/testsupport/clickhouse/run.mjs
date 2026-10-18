import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {request as httpsRequest} from 'node:https';
import {randomUUID} from 'node:crypto';
import {writeFileSync,readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {basename,dirname,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {isMissingDockerResource} from '../docker-qa.mjs';
const execute=promisify(execFile),directory=fileURLToPath(new URL('.',import.meta.url));
const port=Number(process.env.JMS_QA_CLICKHOUSE_PORT||15481),health=Number(process.env.JMS_QA_CLICKHOUSE_HEALTH_PORT||15482);
if(![port,health].every(p=>Number.isInteger(p)&&p>0&&p<65536))throw new Error('Invalid ClickHouse QA ports');
const name=`jms233-clickhouse-${randomUUID()}`,root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid QA owner');
const owner=root?basename(root):name,certDir=mkdtempSync(resolve(tmpdir(),'jms233-clickhouse-cert-'));let stopping=false;
const record={name,owner,cert_directory:certDir};if(root)writeFileSync(resolve(root,'clickhouse-container.json'),JSON.stringify(record));if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,'jumpserver233-clickhouse-ci.json'),JSON.stringify(record));
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('ClickHouse fixture owner changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}const p=resolve(certDir);if(dirname(p).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(p).startsWith('jms233-clickhouse-cert-'))throw new Error('Invalid certificate path');rmSync(p,{recursive:true,force:true});}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0);}catch{process.stderr.write('ClickHouse cleanup failed; preserve owner record.\n');process.exit(1);}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
try{
 await execute('go',['run','./testsupport/mysql/cert',certDir],{cwd:resolve(directory,'../..')});
 const args=['run','--detach','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--label',`com.jumpserver233.qa.workspace=${fileURLToPath(new URL('../../../',import.meta.url))}`,'--publish',`127.0.0.1:${port}:8443`,'--user','0','--env','CLICKHOUSE_USER=qadb','--env','CLICKHOUSE_PASSWORD=synthetic-clickhouse-query-233','--env','CLICKHOUSE_DB=qa','--env','CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1','--mount',`type=bind,source=${certDir},target=/qa-input,readonly`,'--mount',`type=bind,source=${resolve(directory,'start.sh')},target=/qa-start.sh,readonly`,'--entrypoint','sh'];
 if(process.env.JMS_QA_CLICKHOUSE_NETWORK){if(!/^[A-Za-z0-9_.-]+$/.test(process.env.JMS_QA_CLICKHOUSE_NETWORK))throw new Error('Invalid QA network');args.push('--network',process.env.JMS_QA_CLICKHOUSE_NETWORK);}
 args.push('clickhouse/clickhouse-server:25.8-alpine','/qa-start.sh');await execute('docker',args);
 const probe=()=>new Promise((accept,reject)=>{const req=httpsRequest({hostname:'127.0.0.1',port,servername:'clickhouse.synthetic.invalid',ca:readFileSync(resolve(certDir,'server.crt')),auth:'qadb:synthetic-clickhouse-query-233',method:'POST',path:'/?database=qa'},res=>{let body='';res.on('data',chunk=>{body+=chunk;if(body.length>32)res.destroy(new Error('Unexpected ClickHouse probe'));});res.once('error',reject);res.once('end',()=>res.statusCode===200&&body.trim()==='1'?accept():reject(new Error('ClickHouse HTTPS not ready')));});req.once('error',reject);req.setTimeout(1500,()=>req.destroy(new Error('ClickHouse HTTPS probe timeout')));req.end('SELECT 1');});
 let ready=false;for(let i=0;i<180;i++){try{await probe();ready=true;break;}catch{if(i%5===0){const state=await execute('docker',['inspect','--format','{{.State.Running}}',name]);if(state.stdout.trim()!=='true')break;}await new Promise(r=>setTimeout(r,500));}}
 if(!ready)throw new Error('ClickHouse did not become ready');
 const metadata={ready:true,protocol:'clickhouse',address:`127.0.0.1:${port}`,network_address:`${name}:8443`,container_name:name,owner,root_ca_pem:readFileSync(resolve(certDir,'server.crt'),'utf8'),server_name:'clickhouse.synthetic.invalid',database:'qa',username:'qadb'};
 const server=createServer((req,res)=>{if(req.url!='/health'||req.method!=='GET'){res.writeHead(404).end();return;}res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(metadata));});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`ClickHouse QA ready on 127.0.0.1:${port}; health ${health}\n`));
}catch(e){process.stderr.write(`ClickHouse startup failed: ${String(e.stderr||e.message).slice(-1200)}\n`);try{const logs=await execute('docker',['logs','--tail','20',name]);process.stderr.write((logs.stderr+logs.stdout).slice(-3000));await execute('docker',['cp',`${name}:/var/log/clickhouse-server/clickhouse-server.err.log`,resolve(certDir,'diagnostic.log')]);const errorLog=readFileSync(resolve(certDir,'diagnostic.log'),'utf8');process.stderr.write(errorLog.split('\n').filter(line=>/Exception:|<Error>|<Fatal>/.test(line)).slice(-8).join('\n').slice(-5000));}catch{}try{await cleanup();}catch{}process.exitCode=1;}
