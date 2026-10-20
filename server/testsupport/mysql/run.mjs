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
const engine=process.env.JMS_QA_SQL_ENGINE||'mysql';if(!['mysql','mariadb'].includes(engine))throw new Error('Invalid QA SQL engine');
const image=engine==='mysql'?'mysql:8.4':'mariadb:11.4';
const port=Number(process.env.JMS_QA_MYSQL_PORT||(engine==='mysql'?15461:15463)),health=Number(process.env.JMS_QA_MYSQL_HEALTH_PORT||(engine==='mysql'?15462:15464));if(![port,health].every(p=>Number.isInteger(p)&&p>0&&p<65536))throw new Error('Invalid SQL QA ports');
const name=`jms233-${engine}-${randomUUID()}`,root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null;
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid QA resource owner');
const owner=root?basename(root):name;
const certDir=mkdtempSync(resolve(tmpdir(),`jms233-${engine}-cert-`));let stopping=false;
const resource={name,owner,cert_directory:certDir};if(root)writeFileSync(resolve(root,`${engine}-container.json`),JSON.stringify(resource));if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,`jumpserver233-${engine}-ci.json`),JSON.stringify(resource));
function cleanCert(){const target=resolve(certDir);if(dirname(target).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(target).startsWith(`jms233-${engine}-cert-`))throw new Error('Invalid QA cert cleanup');rmSync(target,{recursive:true,force:true});}
async function cleanup(){try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('SQL fixture owner changed');await execute('docker',['rm','--force','--volumes',name]);}catch(e){if(!isMissingDockerResource(e))throw e;}cleanCert();}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0);}catch{process.stderr.write('Owned SQL cleanup failed; preserve resource record.\n');process.exit(1);}}process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
try{
 await execute('go',['run','./testsupport/mysql/cert',certDir],{cwd:resolve(directory,'../..'),maxBuffer:1024*1024});
 const args=['run','--detach','--name',name,'--user','0','--label',`com.jumpserver233.qa.owner=${owner}`,'--label',`com.jumpserver233.qa.workspace=${fileURLToPath(new URL('../../../',import.meta.url))}`,'--publish',`127.0.0.1:${port}:3306`,'--env','MYSQL_ROOT_PASSWORD=synthetic-mysql-root-233','--env','MYSQL_DATABASE=qa','--env','MYSQL_USER=qadb','--env','MYSQL_PASSWORD=synthetic-mysql-query-233','--mount',`type=bind,source=${certDir},target=/qa-input,readonly`,'--mount',`type=bind,source=${resolve(directory,'start.sh')},target=/qa-start.sh,readonly`,'--entrypoint','sh'];
 if(process.env.JMS_QA_MYSQL_NETWORK){if(!/^[A-Za-z0-9_.-]+$/.test(process.env.JMS_QA_MYSQL_NETWORK))throw new Error('Invalid QA network');args.push('--network',process.env.JMS_QA_MYSQL_NETWORK);}args.push(image,'/qa-start.sh',engine==='mysql'?'mysqld':'mariadbd');await execute('docker',args);
 let ready=false;const executable=engine==='mysql'?'mysql':'mariadb';for(let i=0;i<180;i++){try{await execute('docker',['exec','--env','MYSQL_PWD=synthetic-mysql-query-233',name,executable,'--ssl-ca=/run/qa-tls/server.crt',...(engine==='mysql'?['--ssl-mode=VERIFY_IDENTITY']:['--ssl-verify-server-cert']),'-h','127.0.0.1','-u','qadb','qa','-Nse','SELECT 1'],{timeout:2000});ready=true;break;}catch{await new Promise(r=>setTimeout(r,500));}}
 if(!ready)throw new Error(`${engine} fixture did not become ready`);
 await execute('docker',['exec','--env','MYSQL_PWD=synthetic-mysql-root-233',name,executable,'-u','root','-e',"CREATE USER 'pam_admin'@'%' IDENTIFIED BY 'synthetic-pam-admin-233'; GRANT CREATE USER ON *.* TO 'pam_admin'@'%'; GRANT SELECT ON mysql.* TO 'pam_admin'@'%'; GRANT SELECT ON qa.* TO 'pam_admin'@'%';"],{timeout:10000});
 const metadata={ready:true,protocol:engine,address:`127.0.0.1:${port}`,network_address:`${name}:3306`,container_name:name,owner,root_ca_pem:readFileSync(resolve(certDir,'server.crt'),'utf8'),server_name:`${engine}.synthetic.invalid`,database:'qa',username:'qadb'};
 const server=createServer((req,res)=>{if(req.url!='/health'||req.method!=='GET'){res.writeHead(404).end();return;}res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(metadata));});server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`${engine} QA ready on 127.0.0.1:${port}; health ${health}\n`));
}catch(e){process.stderr.write(`SQL fixture startup failed: ${String(e.stderr||e.message).slice(-1000)}\n`);try{await cleanup();}catch{}process.exitCode=1;}
