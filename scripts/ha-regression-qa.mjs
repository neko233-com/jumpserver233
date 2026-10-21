// Verify the shared-auth and takeover regressions with disposable PostgreSQL/SSH.
import {execFile,spawn} from "node:child_process";
import {promisify} from "node:util";
import {createServer} from "node:net";
import {randomUUID} from "node:crypto";
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,existsSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {inspectQAContainers,inspectQAImages,removeUnusedQAImages,removeOwnedTree,removeLocalBuildHistory} from "./qa-lifecycle.mjs";
import {fixtureDiagnostic} from "../server/testsupport/ci-health.mjs";
import {retainQAArtifacts} from "./qa-retention.mjs";
const root=fileURLToPath(new URL("..",import.meta.url)),args=process.argv.slice(2),full=args.includes("--full");
if(full)args.splice(args.indexOf("--full"),1);
const batch=args.length===0?"ha-regression":args.length===2&&args[0]==="--batch"&&/^[a-z][a-z0-9-]{0,63}$/.test(args[1])?args[1]:null;
if(!batch)throw Error("Use [--batch lowercase-name] [--full]");
const out=resolve(root,".cache/qa-reports",batch);mkdirSync(out,{recursive:true});
const temporary=mkdtempSync(resolve(root,".cache/ha-regression-")),db="jms233-postgres-"+randomUUID();
const execute=promisify(execFile),run=(cmd,a,options={})=>execute(cmd,a,{cwd:root,windowsHide:true,maxBuffer:32*1024*1024,...options});
const env={...Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.startsWith("JMS_"))),RUNNER_TEMP:temporary};
const report={at:new Date().toISOString(),pid:process.pid,status:"running",scope:full?"full-go-with-ha-ssh":"ha-auth-logging-regression",database:db,temporaryDirectory:temporary,tests:[],cleanup:{}};
let sshChild,sshImage,pulledDatabase=false,sshDiagnostic="";
const save=()=>{writeFileSync(resolve(out,"summary.json"),JSON.stringify(report,null,2));writeFileSync(resolve(out,"lifecycle.json"),JSON.stringify({at:report.at,pid:process.pid,status:report.status,kind:"ha-regression"}));};
async function freePort(){const s=createServer();await new Promise((ok,no)=>{s.once("error",no);s.listen(0,"127.0.0.1",ok)});const p=s.address().port;await new Promise(ok=>s.close(ok));return p;}
async function wait(read){for(let n=0;n<300;n++){try{const v=await read();if(v)return v}catch{}await new Promise(ok=>setTimeout(ok,200))}throw Error("Owned HA fixture readiness timed out")}
async function cleanup(){
 const record=resolve(temporary,"jumpserver233-keyhost-ci.json");
 if(existsSync(record)){
  const r=JSON.parse(readFileSync(record,"utf8"));if(!/^jms233-keyhost-[a-f0-9-]{36}$/.test(r.name)||r.owner!==r.name)throw Error("Invalid owned SSH receipt");
  for(const c of await inspectQAContainers(run,[r.name])){
   if(c.Config.Labels["com.jumpserver233.qa.owner"]!==r.owner||resolve(c.Config.Labels["com.jumpserver233.qa.workspace"])!==resolve(root))throw Error("SSH ownership changed");
   sshImage=c.Image;await run("docker",["rm","--force","--volumes",c.Id]);
  }
 }
 if(sshChild?.exitCode===null&&sshChild.signalCode===null){const exited=new Promise(ok=>sshChild.once("exit",ok));sshChild.kill();await exited;}
 for(const c of await inspectQAContainers(run,[db])){
  if(c.Config.Labels["com.jumpserver233.qa.owner"]!==db||resolve(c.Config.Labels["com.jumpserver233.qa.workspace"])!==resolve(root))throw Error("Database ownership changed");
  await run("docker",["rm","--force","--volumes",c.Id]);
 }
 for(const [id,tag] of [[sshImage,"jms233-openssh-qa:local"],[pulledDatabase?"postgres:17":null,"postgres:17"]])if(id){
  const [image]=await inspectQAImages(run,[id]);
  if(image&&image.RepoTags?.length===1&&image.RepoTags[0]===tag)report.cleanup.removedImages=(report.cleanup.removedImages||0)+await removeUnusedQAImages(run,[image.Id]);
 }
 report.cleanup.removedBuildHistory=await removeLocalBuildHistory(run,root);
}
try{
 report.commit=(await run("git",["rev-parse","HEAD"])).stdout.trim();
 if((await run("git",["-c","core.fsmonitor=false","-c","core.untrackedCache=false","status","--porcelain","--untracked-files=all"])).stdout.trim())throw Error("Commit the regression batch before provenance verification");
 save();
 const [dbPort,sshPort,healthPort]=await Promise.all([freePort(),freePort(),freePort()]);
 pulledDatabase=(await inspectQAImages(run,["postgres:17"])).length===0;
 await run("docker",["run","--detach","--name",db,"--label",`com.jumpserver233.qa.owner=${db}`,"--label",`com.jumpserver233.qa.workspace=${root}`,"--publish",`127.0.0.1:${dbPort}:5432`,"--tmpfs","/var/lib/postgresql/data:rw,size=1g","--env","POSTGRES_USER=jumpserver","--env","POSTGRES_PASSWORD=synthetic-ha-regression-only","--env","POSTGRES_DB=jumpserver_test","postgres:17"]);
 await wait(async()=>{await run("docker",["exec",db,"pg_isready","-U","jumpserver","-d","jumpserver_test"]);return true});
 sshChild=spawn(process.execPath,[resolve(root,"server/testsupport/openssh/run.mjs")],{cwd:root,env:{...env,JMS_QA_KEYHOST_SSH_PORT:String(sshPort),JMS_QA_KEYHOST_HTTP_PORT:String(healthPort)},windowsHide:true,stdio:["ignore","ignore","pipe"]});
 sshChild.stderr.on("data",b=>{sshDiagnostic=(sshDiagnostic+b.toString()).slice(-16000)});
 const meta=await wait(async()=>{const r=await fetch(`http://127.0.0.1:${healthPort}/health`,{signal:AbortSignal.timeout(1000)});const m=await r.json();return m.ready&&/^jms233-keyhost-[a-f0-9-]{36}$/.test(m.container_name)&&m.fingerprint?.startsWith("SHA256:")?m:null});
 report.realSSH=true;report.phase="go-regressions";save();
 await run("go",["generate","./internal/agentbundle"],{cwd:resolve(root,"server"),env});
 mkdirSync(resolve(temporary,"go-tmp"));mkdirSync(resolve(temporary,"test-tmp"));
 let goResult;
 try{
  const packages=full?["./...","github.com/microsoft/go-mssqldb","github.com/adfnekc/grdp/protocol/sec","github.com/adfnekc/grdp/emission"]:["./cmd/server","./internal/core/auth","./internal/api"];
  goResult=await run("go",["test","-json","-count=1","-timeout","20m","-p","1",...packages],{cwd:resolve(root,"server"),env:{...env,GOTMPDIR:resolve(temporary,"go-tmp"),TMP:resolve(temporary,"test-tmp"),TEMP:resolve(temporary,"test-tmp"),JMS_TEST_DATABASE_URL:`postgres://jumpserver:synthetic-ha-regression-only@127.0.0.1:${dbPort}/jumpserver_test?sslmode=disable`,JMS_TEST_KEY_HOST_ADDR:meta.address,JMS_TEST_KEY_HOST_FINGERPRINT:meta.fingerprint,JMS_TEST_KEY_HOST_NAME:meta.container_name},timeout:30*60*1000});
 }catch(e){goResult=e;report.goDiagnostic=fixtureDiagnostic(String(e.stderr||e.message));}
 const outputs=new Map();
 for(const line of String(goResult.stdout||"").split(/\r?\n/)){
  let event;try{event=JSON.parse(line)}catch{continue}
  if(event.Test&&event.Output){const key=event.Package+"/"+event.Test;outputs.set(key,(outputs.get(key)||"")+event.Output)}
  if(["pass","skip","fail"].includes(event.Action))report.tests.push({package:event.Package,test:event.Test,status:event.Action,seconds:event.Elapsed});
 }
 const required=["TestActiveStandbyFailoverKeepsSharedAuthSession","TestPasswordSharedChallengeAndSecurityEpochSurviveFailover","TestRequestLogPathRedactsWebSocketCapabilities","TestAccessAndPanicLogsNeverContainWebSocketSessionCapability"];
 const failed=report.tests.filter(t=>t.status==="fail");
 if(failed.length){report.failures=failed.map(t=>({test:t.test,diagnostic:fixtureDiagnostic(outputs.get(t.package+"/"+t.test)||"")}));throw Error("Go regression packages failed")}
 for(const name of required)if(!report.tests.some(t=>t.test===name&&t.status==="pass"))throw Error("Required regression did not pass: "+name);
 if((await run("git",["rev-parse","HEAD"])).stdout.trim()!==report.commit||(await run("git",["-c","core.fsmonitor=false","-c","core.untrackedCache=false","status","--porcelain","--untracked-files=all"])).stdout.trim())throw Error("Source changed during HA regression verification");
 report.sourceUnchanged=true;report.status="passed";
}catch(e){report.status="failed";report.diagnostic=fixtureDiagnostic(e.message);if(sshDiagnostic)report.fixtureDiagnostic=fixtureDiagnostic(sshDiagnostic);process.exitCode=1}
finally{
 for(let n=0;n<2;n++){try{await cleanup();report.cleanup[n?"idempotent":"removed"]=true}catch(e){report.status="cleanup_failed";report.cleanup.error=fixtureDiagnostic(e.message);process.exitCode=1}}
 if(report.cleanup.removed&&report.cleanup.idempotent){try{removeOwnedTree(temporary,resolve(root,".cache"),"ha-regression-");report.cleanup.temporaryDataRemoved=true}catch{report.status="cleanup_failed";process.exitCode=1}}
 save();writeFileSync(resolve(out,"cleanup.json"),JSON.stringify({cleaned:report.cleanup.removed&&report.cleanup.idempotent&&report.cleanup.temporaryDataRemoved,temporaryDataRemoved:!!report.cleanup.temporaryDataRemoved}));
 retainQAArtifacts(root,{currentRun:out});
 console.log(JSON.stringify({status:report.status,tests:report.tests.filter(t=>t.test).length,cleanup:report.cleanup,diagnostic:report.diagnostic}));
}
