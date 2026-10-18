import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {createConnection} from 'node:net';
import {randomUUID} from 'node:crypto';
import {writeFileSync,readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {basename,dirname,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {buildQAImage,isMissingDockerResource} from '../docker-qa.mjs';
const execute=promisify(execFile),directory=fileURLToPath(new URL('.',import.meta.url));
const port=Number(process.env.JMS_QA_TELNET_PORT||16523),tls=Number(process.env.JMS_QA_TELNET_TLS_PORT||16992),health=Number(process.env.JMS_QA_TELNET_HEALTH_PORT||16524);
if(![port,tls,health].every(p=>Number.isInteger(p)&&p>0&&p<65536)||new Set([port,tls,health]).size!==3)throw new Error('Invalid Telnet QA ports');
const name=`jms233-telnet-${randomUUID()}`,root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid QA owner');
const owner=root?basename(root):name,certDir=mkdtempSync(resolve(tmpdir(),'jms233-telnet-cert-'));let stopping=false;
const record={name,owner,cert_directory:certDir};if(root)writeFileSync(resolve(root,'telnet-container.json'),JSON.stringify(record));if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,'jumpserver233-telnet-ci.json'),JSON.stringify(record));
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('Telnet fixture owner changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}const p=resolve(certDir);if(dirname(p).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(p).startsWith('jms233-telnet-cert-'))throw new Error('Invalid certificate path');rmSync(p,{recursive:true,force:true});}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0);}catch{process.stderr.write('Telnet cleanup failed; preserve owner record.\n');process.exit(1);}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
function reachable(p){return new Promise(r=>{const c=createConnection({host:'127.0.0.1',port:p});let done=false;const finish=v=>{if(done)return;done=true;c.destroy();r(v)};c.setTimeout(1000,()=>finish(false));c.once('connect',()=>finish(true));c.once('error',()=>finish(false));});}
try{
 await execute('go',['run','./testsupport/mysql/cert',certDir],{cwd:resolve(directory,'../..')});
 await buildQAImage(execute,['build','--tag','jms233-telnet-qa:local',directory]);
 const args=['run','--detach','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--label',`com.jumpserver233.qa.workspace=${fileURLToPath(new URL('../../../',import.meta.url))}`,'--publish',`127.0.0.1:${port}:23`,'--publish',`127.0.0.1:${tls}:992`,'--mount',`type=bind,source=${certDir},target=/qa-input,readonly`];
 const network=process.env.JMS_QA_TELNET_NETWORK;if(network){if(!/^[A-Za-z0-9_.-]+$/.test(network))throw new Error('Invalid QA network');args.push('--network',network);}args.push('jms233-telnet-qa:local');await execute('docker',args);
 let ready=false;for(let i=0;i<120;i++){if(await reachable(port)&&await reachable(tls)){ready=true;break;}await new Promise(r=>setTimeout(r,500));}if(!ready)throw new Error('Telnet fixture did not become ready');
 const metadata={ready:true,address:`127.0.0.1:${tls}`,plaintext_address:`127.0.0.1:${port}`,network_address:`${name}:992`,plaintext_network_address:`${name}:23`,container_name:name,owner,username:'telnetqa',server_name:'telnet.synthetic.invalid',root_ca_pem:readFileSync(resolve(certDir,'server.crt'),'utf8')};
 const server=createServer((req,res)=>{if(req.method!=='GET'||req.url!=='/health'){res.writeHead(404).end();return;}res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify(metadata));});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`Telnet QA ready on TLS ${tls} / plain ${port}; health ${health}\n`));
}catch{process.stderr.write('Telnet fixture startup failed.\n');try{const r=await execute('docker',['logs','--tail','10',name]);process.stderr.write((r.stdout+r.stderr).slice(-1200));}catch{}try{await cleanup();}catch{process.stderr.write('Owned Telnet resources need cleanup.\n');}process.exitCode=1;}
