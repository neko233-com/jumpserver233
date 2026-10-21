// Uses only the owning native QA namespace; no capability or private key is reported.
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const base="/api/v1/accounts/rotation-";
async function until(read,accept,message){for(let n=0;n<450;n++){const value=await read();if(accept(value))return value;await delay(100)}throw Error(message)}
async function finished(api,token,id){return until(()=>api("GET",base+"runs/"+id,undefined,token),r=>!["queued","running"].includes(r.state),"Account check did not finish")}
function metadataOnly(value,secrets){const text=JSON.stringify(value);if(secrets.some(secret=>text.includes(secret))||text.includes('"fixed_secret_id"')||text.includes('"fixed_password"')||text.includes('"Intents"'))throw Error("Account check exposed credential material")}

export async function verifyAccountChecks({page,context,expect,api,admin,run,runInput,owner,sshHost,fingerprint,output,report}){
 report.accountChecksStep="fixtures";
 const password="synthetic-check-account-233",platformPassword="NativeCheckOnly-233!",fixed="Ef4?".repeat(16),name="Native account authentication checks",marker="/tmp/jms233-check-opened-session";
 await run("docker",["exec",sshHost,"sh","-ceu","for u in managedqa_checkparent managedqa_checked managedqa_checkkey; do useradd --create-home --user-group --shell /bin/bash \"$u\"; printf '%s\\n' \"$u:synthetic-check-account-233\" | chpasswd; done; printf '%s\\n' '#!/bin/sh' 'touch /tmp/jms233-check-opened-session' 'exec /bin/bash \"$@\"' >/usr/local/bin/qa-check-shell; chmod 0755 /usr/local/bin/qa-check-shell; usermod --shell /usr/local/bin/qa-check-shell managedqa_checked; install -d -m 0700 -o managedqa_checkkey -g managedqa_checkkey /home/managedqa_checkkey/.ssh"]);
 const pair=generateKeyPairSync("ed25519"),privateKey=pair.privateKey.export({type:"pkcs8",format:"pem"}).toString(),publicRaw=pair.publicKey.export({type:"spki",format:"der"}).subarray(-32),wire=Buffer.concat([Buffer.from([0,0,0,11]),Buffer.from("ssh-ed25519"),Buffer.from([0,0,0,32]),publicRaw]);
 await runInput("docker",["exec","-i",sshHost,"sh","-ceu","umask 077; cat >/home/managedqa_checkkey/.ssh/authorized_keys; chown managedqa_checkkey:managedqa_checkkey /home/managedqa_checkkey/.ssh/authorized_keys"],"ssh-ed25519 "+wire.toString("base64")+"\n");
 const gateway=await api("POST","/api/v1/assets",{name:"Account check gateway",host:sshHost,port:22,username:"keyqa",password:"synthetic-keyhost-password-233",host_key_fingerprint:fingerprint},admin,201);
 const parent=await api("POST","/api/v1/assets",{name:"Account check parent",host:"127.0.0.1",port:22,username:"managedqa_checkparent",password,host_key_fingerprint:fingerprint,gateway_id:gateway.id},admin,201);
 const accountsPath=`/api/v1/assets/${parent.id}/accounts`,current=()=>api("GET",accountsPath,undefined,admin);
 const defaultAccount=(await current()).results.find(a=>a.default);
 const named=await api("POST",accountsPath,{username:"managedqa_checked",password,password_rotation_enabled:false,version:defaultAccount.version},admin,201);
 const key=await api("POST",accountsPath,{username:"managedqa_checkkey",credential_type:"ssh_key",private_key:privateKey,key_rotation_enabled:false,version:(await current()).results.find(a=>a.default).version},admin,201);
 const alias=await api("POST","/api/v1/assets",{name:"Account check alias",host:"127.0.0.1",port:22,username:"managedqa_checked",password,host_key_fingerprint:fingerprint,gateway_id:gateway.id},admin,201);
 const checker=await api("POST","/api/v1/users",{username:"native.checker",password:platformPassword,role:"operator"},admin,201);
 let role=await api("POST","/api/v1/rbac/roles",{name:"Native check-only",permissions:["assets.view_all","assets.probe","accounts.rotation.view","accounts.rotation.manage","accounts.rotation.check"]},admin,201);
 await api("PUT","/api/v1/rbac/bindings",{subject_type:"user",subject_id:checker.id,role_ids:[role.id]},admin);
 const token=(await api("POST","/api/v1/authentication/auth/",{username:checker.username,password:platformPassword})).access_token;
 let plan=await api("POST",base+"plans",{name,kind:"manual",targets:[{account_id:named.id,collector_id:parent.id},{account_id:alias.id},{account_id:key.id}],request_id:randomUUID()},token,201);
 if(plan.check_enabled||plan.next_check)throw Error("Connectivity checks were enabled by default");
 report.accountChecksStep="schedule_browser";
 await page.reload();await page.getByRole("row").filter({hasText:name}).getByRole("button",{name:"Edit plan",exact:true}).click();
 const editor=page.getByRole("dialog",{name:"Edit plan",exact:true});await editor.getByRole("checkbox",{name:"Check stored credentials periodically",exact:true}).check();await editor.getByLabel("Check interval in hours (1–720)",{exact:true}).fill("1");await editor.getByRole("button",{name:"Save plan",exact:true}).click();await expect(editor).toHaveCount(0);
 plan=await until(()=>api("GET",base+"plans/"+plan.id,undefined,admin),p=>Boolean(p.last_check_run_id),"Periodic account check was not dispatched");
 const scheduled=await finished(api,admin,plan.last_check_run_id);if(!scheduled.scheduled||scheduled.operation!=="check"||scheduled.state!=="succeeded"||scheduled.items.length!==3)throw Error("Periodic account check did not verify passwords, aliases and keys");
 const before=(await current()).results.map(a=>({id:a.id,revision:a.credential_revision})).sort((a,b)=>a.id.localeCompare(b.id));
 const fixedInput={name:plan.name,kind:plan.kind,revision:plan.revision,targets:plan.targets,check_enabled:true,check_interval_hours:1,password_mode:"fixed",fixed_password:fixed,request_id:randomUUID()};
 plan=await api("PUT",base+"plans/"+plan.id,fixedInput,admin);
 const fixedScheduledPlan=await until(()=>api("GET",base+"plans/"+plan.id,undefined,admin),p=>p.last_check_run_id&&p.last_check_run_id!==scheduled.id,"Fixed-plan connectivity schedule was not dispatched");
 const fixedScheduled=await finished(api,admin,fixedScheduledPlan.last_check_run_id);if(fixedScheduled.state!=="succeeded"||fixedScheduled.operation!=="check"||fixedScheduled.password_mode)throw Error("Checks copied or required the fixed-password strategy");metadataOnly(fixedScheduled,[password,privateKey,fixed]);
 await api("POST",base+`plans/${plan.id}/runs`,{request_id:randomUUID()},token,403);
 // Switch the browser to the dedicated checker; the original admin API token stays local.
 await page.getByRole("button",{name:"Sign out",exact:true}).click();await page.waitForURL(/\/login$/);
 await page.getByRole("textbox",{name:"Username",exact:true}).fill(checker.username);await page.getByRole("textbox",{name:"Password",exact:true}).fill(platformPassword);await Promise.all([page.waitForURL(/\/console$/),page.getByRole("button",{name:"Sign in",exact:true}).click()]);
 await page.goto(new URL("/console/rotation-plans",page.url()).href);
 await expect(page.getByRole("row").filter({hasText:name}).getByRole("button",{name:"Check current credentials",exact:true})).toBeVisible();await expect(page.getByRole("row").filter({hasText:name}).getByRole("button",{name:"Rotate now",exact:true})).toHaveCount(0);
 report.accountChecksStep="manual_browser";
 const submit=async()=>{
  await page.getByRole("row").filter({hasText:name}).getByRole("button",{name:"Check current credentials",exact:true}).click();
  const confirmation=page.getByRole("dialog",{name:"Check stored SSH credentials",exact:true});
  const requests=[],responses=[];
  const sent=r=>{if(r.request().method()==="POST")responses.push({path:new URL(r.url()).pathname,status:r.status()})};
  const started=r=>{if(r.method()==="POST")requests.push(new URL(r.url()).pathname)};
  page.on("response",sent);page.on("request",started);
  try{
   const [response]=await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname===base+`plans/${plan.id}/checks`&&r.request().method()==="POST"),confirmation.getByRole("button",{name:"Check current credentials",exact:true}).click()]);
   if(response.status()!==202)throw Error("Check-only browser could not submit authentication");return {run:await response.json(),input:response.request().postDataJSON()};
  }catch(e){
   report.accountCheckBrowserFailure={requests:requests.slice(-5),responses:responses.slice(-5),url:new URL(page.url()).pathname,alerts:await page.getByRole("alert").allTextContents(),buttons:await page.getByRole("button").allTextContents()};
   await page.screenshot({path:resolve(output,"account-check-failure.png")}).catch(()=>{});throw e;
  }finally{page.off("response",sent);page.off("request",started)}
 };
 const positive=await submit(),success=await finished(api,token,positive.run.id);if(success.state!=="succeeded"||success.operation!=="check"||success.items.some(a=>a.after_revision||a.linked_to))throw Error("Manual check changed credential state");
 const detail=page.getByRole("dialog",{name:"Connectivity results",exact:true});await expect(detail.getByRole("status")).toHaveText("Succeeded",{timeout:45000});
 const replay=await context.request.post(new URL(base+`plans/${plan.id}/checks`,page.url()).href,{data:positive.input});if(replay.status()!==202||(await replay.json()).id!==success.id)throw Error("Browser account check replay was not idempotent");
 const cli=async args=>JSON.parse((await runInput("docker",["exec","-i",owner,"sh","-ceu",'IFS= read -r JMS_TOKEN; export JMS_TOKEN; JMS_SERVER_URL=http://127.0.0.1:8080 exec /tmp/controller/jms "$@"',"qa-check-cli",...args],token+"\n")).stdout);
 const fromCLI=await cli(["account","rotation","check",plan.id,"--request-id",positive.input.request_id,"--wait"]);if(fromCLI.id!==success.id)throw Error("CLI check replay changed run identity");
 await detail.getByRole("button",{name:"Close",exact:true}).click();
 report.accountChecksStep="credential_drift";
 await runInput("docker",["exec","-i",sshHost,"chpasswd"],"managedqa_checked:synthetic-remote-drift-233\n");
 const negative=await submit(),failed=await finished(api,token,negative.run.id);if(failed.state!=="partial"||failed.items.filter(a=>a.error_code==="authentication_failed").length!==2)throw Error("Account credential drift was not detected");
 await expect(detail.getByRole("status")).toHaveText("Partially succeeded",{timeout:45000});metadataOnly(failed,[password,privateKey,fixed]);await detail.screenshot({path:resolve(output,"account-checks.en.png")});
 const notification=await until(()=>api("GET","/api/v1/notifications/inbox?limit=100",undefined,token),p=>p.results?.some(m=>m.source?.kind==="account_checks"&&m.source.id===failed.id),"Failed account check did not reach security notifications");
 if(!notification.results.some(m=>m.source?.id===failed.id&&m.topic==="security"))throw Error("Account check failure used an incorrect notification topic");
 const source=await api("GET","/api/v1/notifications/sources/account_checks/"+failed.id,undefined,token);if(source.id!==failed.id||source.accounts!==3)throw Error("Account check notification details differ");metadataOnly(source,[password,privateKey,fixed]);
 await runInput("docker",["exec","-i",sshHost,"chpasswd"],"managedqa_checked:"+password+"\n");
 await detail.getByRole("button",{name:"Retry unsuccessful accounts",exact:true}).click();const retryDialog=page.getByRole("dialog",{name:"Retry unsuccessful connectivity checks",exact:true});
 const [retried]=await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname===base+`runs/${failed.id}/retry`&&r.request().method()==="POST"),retryDialog.getByRole("button",{name:"Submit retry",exact:true}).click()]);if(retried.status()!==202)throw Error("Check-only retry was rejected");const child=await finished(api,token,(await retried.json()).id);if(child.state!=="succeeded"||child.operation!=="check"||child.items.length!==2||child.items.some(a=>a.account_id===key.id))throw Error("Connectivity retry repeated a successful key account");
 await expect(detail.getByRole("status")).toHaveText("Succeeded",{timeout:45000});await detail.getByRole("button",{name:"Close",exact:true}).click();
 await page.getByRole("button",{name:"中文",exact:true}).click();await page.setViewportSize({width:390,height:844});await page.getByRole("row").filter({hasText:name}).getByRole("button",{name:"最近连接性结果",exact:true}).click();
 const chinese=page.getByRole("dialog",{name:"连接性检测结果",exact:true});if(!await chinese.evaluate(el=>el.scrollWidth<=el.clientWidth+1)||!await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1))throw Error("Account checks overflow a narrow viewport");const results=chinese.getByRole("region",{name:"账号",exact:true});if(!await results.evaluate(el=>el.scrollWidth<=el.clientWidth+1))throw Error("Account check result columns need horizontal scrolling on mobile");await results.scrollIntoViewIfNeeded();await results.screenshot({path:resolve(output,"account-checks.zh.png")});await chinese.getByRole("button",{name:"关闭",exact:true}).click();await page.getByRole("button",{name:"EN",exact:true}).click();await page.setViewportSize({width:1280,height:900});
 const after=(await current()).results.map(a=>({id:a.id,revision:a.credential_revision})).sort((a,b)=>a.id.localeCompare(b.id));if(JSON.stringify(before)!==JSON.stringify(after))throw Error("Account checks changed a stored credential revision");
 await run("docker",["exec",sshHost,"test","!","-e",marker]);
 const job=await api("POST","/api/v1/ops/jobs",{asset_id:alias.id,command:"printf account_check_ssh_ok",timeout_seconds:15,request_id:randomUUID()},admin,201);
 await until(()=>api("GET","/api/v1/ops/jobs/"+job.id,undefined,admin),j=>j.state==="succeeded"&&j.stdout==="account_check_ssh_ok","SSH positive control after account checks failed");await run("docker",["exec",sshHost,"test","-e",marker]);
 plan=await api("GET",base+"plans/"+plan.id,undefined,admin);plan=await api("PUT",base+"plans/"+plan.id,{...fixedInput,revision:plan.revision,check_enabled:false,fixed_password:undefined,request_id:randomUUID()},admin);if(plan.next_check||plan.check_enabled)throw Error("Account check schedule did not stop");
 role=await api("PUT","/api/v1/rbac/roles/"+role.id,{name:role.name,revision:role.revision,permissions:["assets.view_all","assets.probe","accounts.rotation.view","accounts.rotation.manage"]},admin);
 await api("POST",base+`plans/${plan.id}/checks`,positive.input,token,403);
 report.accountChecksStep="complete";
 return {planID:plan.id,parentID:parent.id,accountIDs:[named.id,alias.id,key.id],scheduledRunID:scheduled.id,fixedScheduledRunID:fixedScheduled.id,failedRunID:failed.id,retryRunID:child.id,checkOnlyRole:true,noRotateOrFixedRights:true,passwordAndKey:true,pinnedGateway:true,aliasesCheckedSeparately:true,mobileResultsWithoutHorizontalScroll:true,defaultOff:true,independentSchedule:true,credentialRevisionsUnchanged:true,noSessionOrCommand:true,positiveCommandControl:true,webAndCLIReplay:true,credentialDriftDetected:true,successfulItemNotRetried:true,securityNotification:true,currentPermissionRevoked:true,languages:["en","zh-CN"],mobileWidth:390};
}

export async function verifyAccountChecksAfterRestart({api,admin,proof}){
 const plan=await api("GET",base+"plans/"+proof.planID,undefined,admin),old=await api("GET",base+"runs/"+proof.retryRunID,undefined,admin);
 if(plan.check_enabled||plan.next_check||old.state!=="succeeded"||old.operation!=="check")throw Error("Restart lost account check configuration or history");
 const submitted=await api("POST",base+`plans/${plan.id}/checks`,{request_id:randomUUID()},admin,202),result=await finished(api,admin,submitted.id);
 if(result.state!=="succeeded"||result.operation!=="check"||result.items.some(i=>i.after_revision))throw Error("Stored password/key checks failed after restart");
 return {encryptedBackupRestore:true,restartHistoryPreserved:true,realAuthenticationAfterRestart:true};
}
