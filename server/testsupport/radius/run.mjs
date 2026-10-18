import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {connect as tlsConnect} from 'node:tls';
import {randomUUID} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {basename,dirname,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {buildQAImage,isMissingDockerResource} from '../docker-qa.mjs';
const execute=promisify(execFile);
const udp=Number(process.env.JMS_QA_RADIUS_UDP_PORT||18512),tls=Number(process.env.JMS_QA_RADIUS_TLS_PORT||18513),health=Number(process.env.JMS_QA_RADIUS_HEALTH_PORT||18514);
if(![udp,tls,health].every(p=>Number.isInteger(p)&&p>0&&p<65536)||new Set([udp,tls,health]).size!==3)throw Error('Invalid RADIUS ports');
const name=`jms233-radius-${randomUUID()}`,root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw Error('Invalid fixture owner');
const owner=root?basename(root):name;
if(root)writeFileSync(resolve(root,'radius-container.json'),JSON.stringify({name,owner}));
if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,'jumpserver233-radius-ci.json'),JSON.stringify({name,owner}));
let stopping=false;
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw Error('Owner changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0)}catch{process.stderr.write('Owned RADIUS cleanup failed; retain record.\n');process.exit(1)}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
function authenticated(ca,cert,key){return new Promise(done=>{const s=tlsConnect({host:'127.0.0.1',port:tls,servername:'radius.synthetic.invalid',ca,cert,key,rejectUnauthorized:true});s.setTimeout(1000);s.once('secureConnect',()=>{s.destroy();done(true)});s.once('error',()=>{s.destroy();done(false)});s.once('timeout',()=>{s.destroy();done(false)})})}
try{
 await buildQAImage(execute,['build','--tag','jms233-radius-qa:local',fileURLToPath(new URL('.',import.meta.url))]);
 const args=['run','--detach','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--label',`com.jumpserver233.qa.workspace=${fileURLToPath(new URL('../../../',import.meta.url))}`,'--publish',`127.0.0.1:${udp}:1812/udp`,'--publish',`127.0.0.1:${tls}:2083`];
 if(process.env.JMS_QA_RADIUS_NETWORK){if(!/^[A-Za-z0-9_.-]+$/.test(process.env.JMS_QA_RADIUS_NETWORK))throw Error('Invalid fixture network');args.push('--network',process.env.JMS_QA_RADIUS_NETWORK)}
 args.push('jms233-radius-qa:local');await execute('docker',args);
 const read=async file=>(await execute('docker',['exec',name,'cat',`/run/qa-tls/${file}`])).stdout;
 let ready=false,ca='',cert='',key='';for(let i=0;i<120;i++){const {stdout}=await execute('docker',['inspect','--format','{{.State.Running}}',name]);if(stdout.trim()!=='true'){const logs=await execute('docker',['logs','--tail','15',name]);throw Error('FreeRADIUS stopped: '+logs.stdout+logs.stderr)}try{ca=await read('ca.crt');cert=await read('client.crt');key=await read('client.key');if(await authenticated(ca,cert,key)){ready=true;break}}catch{}await new Promise(r=>setTimeout(r,500))}if(!ready)throw Error('FreeRADIUS startup deadline');
 const meta={ready:true,container_name:name,owner,udp_port:udp,tls_port:tls,server_name:'radius.synthetic.invalid',root_ca_pem:ca,client_certificate:cert};
 const server=createServer((req,res)=>{if(req.method!=='GET'||!['/health','/credentials'].includes(req.url)){res.writeHead(404).end();return}res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(req.url==='/credentials'?{...meta,client_key:key,shared_secret:'synthetic-radius-shared-secret-233'}:meta))});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`FreeRADIUS QA ready: UDP ${udp}, mTLS ${tls}, health ${health}\n`));
}catch(e){process.stderr.write(`RADIUS fixture startup failed: ${String(e.stderr||e.message).slice(-1200)}\n`);try{await cleanup()}catch{}process.exitCode=1}
