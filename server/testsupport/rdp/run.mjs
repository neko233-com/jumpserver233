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
const port=Number(process.env.JMS_QA_RDP_PORT||19389),health=Number(process.env.JMS_QA_RDP_HEALTH_PORT||19390);
if(![port,health].every(p=>Number.isInteger(p)&&p>0&&p<65536)||new Set([port,health]).size!==2)throw new Error('Invalid RDP QA ports');
const name=`jms233-rdp-${randomUUID()}`,root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid QA owner');
const owner=root?basename(root):name,certDir=mkdtempSync(resolve(tmpdir(),'jms233-rdp-cert-'));let stopping=false;
const record={name,owner,cert_directory:certDir};if(root)writeFileSync(resolve(root,'rdp-container.json'),JSON.stringify(record));if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,'jumpserver233-rdp-ci.json'),JSON.stringify(record));
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('RDP fixture owner changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}const p=resolve(certDir);if(dirname(p).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(p).startsWith('jms233-rdp-cert-'))throw new Error('Invalid certificate path');rmSync(p,{recursive:true,force:true});}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0);}catch{process.stderr.write('RDP cleanup failed; preserve owner record.\n');process.exit(1);}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
function reachable(p){return new Promise(r=>{const c=createConnection({host:'127.0.0.1',port:p});let done=false;const finish=v=>{if(done)return;done=true;c.destroy();r(v)};c.setTimeout(1000,()=>finish(false));c.once('connect',()=>finish(true));c.once('error',()=>finish(false));});}
try{
 await execute('go',['run','./testsupport/mysql/cert',certDir],{cwd:resolve(directory,'../..')});
 await buildQAImage(execute,['build','--tag','jms233-rdp-qa:local',directory]);
 const args=['run','--detach','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--publish',`127.0.0.1:${port}:3389`,'--mount',`type=bind,source=${certDir},target=/qa-input,readonly`];
 const network=process.env.JMS_QA_RDP_NETWORK;if(network){if(!/^[A-Za-z0-9_.-]+$/.test(network))throw new Error('Invalid QA network');args.push('--network',network);}args.push('jms233-rdp-qa:local');await execute('docker',args);
 let ready=false;for(let i=0;i<120;i++){if(await reachable(port)){ready=true;break;}await new Promise(r=>setTimeout(r,500));}if(!ready)throw new Error('RDP fixture did not become ready');
 const metadata={ready:true,address:`127.0.0.1:${port}`,network_address:`${name}:3389`,container_name:name,owner,username:'rdpqa',server_name:'rdp.synthetic.invalid',root_ca_pem:readFileSync(resolve(certDir,'server.crt'),'utf8')};
 const server=createServer(async (req,res)=>{if(req.method==="GET"&&req.url==="/state"){try{const {stdout}=await execute("docker",["exec",name,"cat","/home/rdpqa/qa-state.json"]);res.writeHead(200,{"Content-Type":"application/json"}).end(stdout);}catch{res.writeHead(503).end();}return;}if(req.method!=='GET'||req.url!=='/health'){res.writeHead(404).end();return;}res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify(metadata));});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`RDP QA ready on TLS ${port}; health ${health}\n`));
}catch{process.stderr.write('RDP fixture startup failed.\n');try{const r=await execute('docker',['logs','--tail','10',name]);process.stderr.write((r.stdout+r.stderr).slice(-1200));}catch{}try{await cleanup();}catch{process.stderr.write('Owned RDP resources need cleanup.\n');}process.exitCode=1;}
