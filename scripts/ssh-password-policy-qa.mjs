// Invoked only inside the owned native runner; credentials stay inside Vault.
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { classifyNativeBrowserLog } from "./native-browser-logs.mjs";
export async function verifySSHPasswordPolicy({run,owner,url,output,api,operator,sshHost,fingerprint,chromium,expect,report,stopSelected,startSelected,inContainer}){
 report.sshPasswordPolicyStep="configuration";
 const path="/api/v1/accounts/password-policy";
 let admin=(await api("POST","/api/v1/authentication/auth/",{username:"root",password:"root"})).access_token;
 const initial=await api("GET",path,undefined,admin);
 await api("GET",path,undefined,await operator(),403);
 const target=await api("POST","/api/v1/assets",{name:"Password policy SSH",host:sshHost,port:22,username:"rotationqa",password:"synthetic-keyhost-password-233",host_key_fingerprint:fingerprint},admin,201);
 const browser=await chromium.launch({headless:true}),errors=[],diagnostics={anonymous_session_probe:0,headless_gpu_readback:0};let saved;
 try{
  const context=await browser.newContext({locale:"en-US",viewport:{width:1280,height:900}}),page=await context.newPage();let authenticated=false;
  page.on("pageerror",e=>errors.push(e.message));page.on("console",m=>{if(!["warning","error"].includes(m.type()))return;const kind=classifyNativeBrowserLog(m.type(),m.text(),m.location().url,url,authenticated);if(kind==="unexpected")errors.push(m.text());else diagnostics[kind]++;});
  await page.goto(url+"/login");await page.getByRole("textbox",{name:"Username",exact:true}).fill("root");await page.getByRole("textbox",{name:"Password",exact:true}).fill("root");await Promise.all([page.waitForURL(url+"/console"),page.getByRole("button",{name:"Sign in",exact:true}).click()]);authenticated=true;
  await page.goto(url+"/console/rotation-plans");await expect(page).toHaveTitle(/jumpserver233/i);await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  const panel=page.getByRole("region",{name:"Generated SSH password policy",exact:true});await expect(panel).toContainText("Policy revision");await panel.locator("summary").filter({hasText:"Configure generated passwords"}).click();
  for(const [name,value] of [["Minimum length",48],["Maximum length",64],["Minimum uppercase letters",4],["Minimum lowercase letters",4],["Minimum digits",5],["Minimum symbols",3]])await panel.getByLabel(name,{exact:true}).fill(String(value));
  await panel.getByLabel("Excluded characters (optional)",{exact:true}).fill("OI1l0");
  const [response]=await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname===path&&r.request().method()==="PUT"),panel.getByRole("button",{name:"Save SSH password policy",exact:true}).click()]);if(response.status()!==200)throw Error("SSH policy browser save failed");
  const input=response.request().postDataJSON();saved=await response.json();await expect(panel.getByRole("status")).toContainText("saved");
  const replay=await context.request.put(url+path,{data:input});if(replay.status()!==200||(await replay.json()).policy.revision!==saved.policy.revision)throw Error("SSH policy receipt replay failed");
  await api("PUT",path,{...input,request_id:randomUUID()},admin,409);await api("PUT",path,input,await operator(),403);
  await panel.screenshot({path:resolve(output,"password-policy.en.png")});
  await page.getByRole("button",{name:"中文",exact:true}).click();await page.setViewportSize({width:390,height:844});const chinese=page.getByRole("region",{name:"SSH 生成密码策略",exact:true});await expect(chinese.getByLabel("最少数字",{exact:true})).toHaveValue("5");if(!await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1))throw Error("SSH policy overflows mobile viewport");await chinese.screenshot({path:resolve(output,"password-policy.zh.png")});
 }finally{await browser.close()}
 if(errors.length)throw Error("SSH policy browser diagnostics failed");
 report.sshPasswordPolicyStep="rotation";
 const rotate=await api("POST",`/api/v1/assets/${target.id}/password-rotation`,undefined,admin);if(rotate.password_rotation?.state!=="scheduled")throw Error("Configured SSH password rotation failed");
 const ssh=async()=>{const job=await api("POST","/api/v1/ops/jobs",{asset_id:target.id,command:"printf policy_ssh_ok",timeout_seconds:15,request_id:randomUUID()},admin,201);for(let n=0;n<150;n++){const v=await api("GET","/api/v1/ops/jobs/"+job.id,undefined,admin);if(v.state==="succeeded"&&v.stdout==="policy_ssh_ok")return;if(["failed","denied","interrupted"].includes(v.state))throw Error("SSH after configured rotation failed");await delay(100)}throw Error("SSH policy job timed out")};await ssh();
 const cli=JSON.parse((await run("docker",["exec",owner,"sh","-ceu",'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/controller/jms account password-policy show'])).stdout);if(cli.policy.revision!==saved.policy.revision)throw Error("SSH policy CLI differs from Web");
 await stopSelected();
 report.sshPasswordPolicyStep="backup";
 const passphrase="synthetic-policy-backup-passphrase";
 await inContainer(["backup","create","--data-dir","/tmp/data","--file","/tmp/policy.jmsbackup","--passphrase-file","-"],passphrase);
 const restored=JSON.parse((await inContainer(["backup","restore","--data-dir","/tmp/policy-restored","--file","/tmp/policy.jmsbackup","--passphrase-file","-"],passphrase)).stdout);
 const again=JSON.parse((await inContainer(["backup","restore","--data-dir","/tmp/policy-restored","--file","/tmp/policy.jmsbackup","--passphrase-file","-"],passphrase)).stdout);if(!again.unchanged||restored.backup_id!==again.backup_id)throw Error("SSH policy backup restore replay failed");
 const hashes=await run("docker",["exec",owner,"sha256sum","/tmp/data/ssh-password-policy.json","/tmp/policy-restored/ssh-password-policy.json"]);const [a,b]=hashes.stdout.trim().split("\n").map(s=>s.split(/\s+/)[0]);if(a!==b)throw Error("Backup lost encrypted SSH policy state");
 const installed=JSON.parse((await inContainer(["update","install-status","--root","/tmp/releases"])).stdout);
 await run("docker",["exec",owner,"sh","-ceu",'JMS_DATA_DIR=/tmp/policy-restored JMS_RELEASE_ROOT= exec "$1" --check-data',"sh",`/tmp/releases/releases/${installed.current.archive_sha256}/jms233-server`]);
 report.sshPasswordPolicyStep="restart";await startSelected("v0.0.7");admin=(await api("POST","/api/v1/authentication/auth/",{username:"root",password:"root"})).access_token;await ssh();
 const final=await api("GET",path,undefined,admin);if(final.policy.revision!==saved.policy.revision||final.audit.length!==initial.audit.length+1)throw Error("Restart changed SSH policy audit/revision");
 report.sshPasswordPolicy={defaultRevision:initial.policy.revision,configuredRevision:saved.policy.revision,webAndCLI:true,receiptReplay:true,staleRevisionRejected:true,nonAdminDenied:true,realSSHRotation:true,realSSHAfterRestart:true,encryptedBackupRestore:true,restoredDataPreflight:true,backupRestoreReplay:true,languages:["en","zh-CN"],mobileWidth:390,pageErrors:errors.length,expectedBrowserDiagnostics:diagnostics};
 report.sshPasswordPolicyStep="complete";
}
