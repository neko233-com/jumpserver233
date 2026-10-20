import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {randomUUID} from 'node:crypto';
import {writeFileSync,readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {basename,dirname,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {isMissingDockerResource} from '../docker-qa.mjs';
const execute=promisify(execFile),directory=fileURLToPath(new URL('.',import.meta.url));
const port=Number(process.env.JMS_QA_SQLSERVER_PORT||15471),health=Number(process.env.JMS_QA_SQLSERVER_HEALTH_PORT||15472);
if(![port,health].every(p=>Number.isInteger(p)&&p>0&&p<65536))throw new Error('Invalid SQL Server QA ports');
const name=`jms233-sqlserver-${randomUUID()}`,root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid QA owner');
const owner=root?basename(root):name,certDir=mkdtempSync(resolve(tmpdir(),'jms233-sqlserver-cert-'));let stopping=false;
const record={name,owner,cert_directory:certDir};if(root)writeFileSync(resolve(root,'sqlserver-container.json'),JSON.stringify(record));if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,'jumpserver233-sqlserver-ci.json'),JSON.stringify(record));
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('SQL Server fixture owner changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}const p=resolve(certDir);if(dirname(p).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(p).startsWith('jms233-sqlserver-cert-'))throw new Error('Invalid certificate path');rmSync(p,{recursive:true,force:true});}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0);}catch{process.stderr.write('SQL Server cleanup failed; preserve owner record.\n');process.exit(1);}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
try{
 await execute('go',['run','./testsupport/mysql/cert',certDir],{cwd:resolve(directory,'../..')});
 const args=['run','--detach','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--label',`com.jumpserver233.qa.workspace=${fileURLToPath(new URL('../../../',import.meta.url))}`,'--publish',`127.0.0.1:${port}:1433`,'--user','0','--env','ACCEPT_EULA=Y','--env','MSSQL_PID=Developer','--env','MSSQL_SA_PASSWORD=Synthetic-SQLServer-Root-233!','--env','MSSQL_MEMORY_LIMIT_MB=1024','--mount',`type=bind,source=${certDir},target=/qa-input,readonly`,'--mount',`type=bind,source=${resolve(directory,'start.sh')},target=/qa-start.sh,readonly`,'--entrypoint','sh'];
 if(process.env.JMS_QA_SQLSERVER_NETWORK){if(!/^[A-Za-z0-9_.-]+$/.test(process.env.JMS_QA_SQLSERVER_NETWORK))throw new Error('Invalid QA network');args.push('--network',process.env.JMS_QA_SQLSERVER_NETWORK);}
 args.push('mcr.microsoft.com/mssql/server:2022-latest','/qa-start.sh');await execute('docker',args);
 const sqlcmd=['exec','--env','SQLCMDPASSWORD=Synthetic-SQLServer-Root-233!',name,'/opt/mssql-tools18/bin/sqlcmd','-S','127.0.0.1','-U','sa','-N','-F','sqlserver.synthetic.invalid','-b','-l','2','-Q'];
 let ready=false;for(let i=0;i<240;i++){try{await execute('docker',[...sqlcmd,'SELECT 1'],{timeout:4000});ready=true;break;}catch{await new Promise(r=>setTimeout(r,500));}}
 if(!ready)throw new Error('SQL Server did not become ready');
 await execute('docker',[...sqlcmd,"CREATE DATABASE qa;"],{timeout:10000});
 await execute('docker',[...sqlcmd,"CREATE LOGIN qadb WITH PASSWORD='Synthetic-SQLServer-Query-233!', CHECK_POLICY=OFF; USE qa; CREATE USER qadb FOR LOGIN qadb; ALTER ROLE db_owner ADD MEMBER qadb;"],{timeout:10000});
 await execute('docker',[...sqlcmd,"CREATE LOGIN pam_admin WITH PASSWORD='Synthetic-PAM-Admin-233!', CHECK_POLICY=OFF; GRANT ALTER ANY LOGIN TO pam_admin; GRANT VIEW ANY DEFINITION TO pam_admin;"],{timeout:10000});
 const metadata={ready:true,protocol:'sqlserver',address:`127.0.0.1:${port}`,network_address:`${name}:1433`,container_name:name,owner,root_ca_pem:readFileSync(resolve(certDir,'server.crt'),'utf8'),server_name:'sqlserver.synthetic.invalid',database:'qa',username:'qadb'};
 const server=createServer((req,res)=>{if(req.url!='/health'||req.method!=='GET'){res.writeHead(404).end();return;}res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(metadata));});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`SQL Server QA ready on 127.0.0.1:${port}; health ${health}\n`));
}catch(e){process.stderr.write(`SQL Server startup failed: ${String(e.stderr||e.message).slice(-1200)}\n`);try{await cleanup();}catch{}process.exitCode=1;}
