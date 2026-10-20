// Full retry acceptance inside the owned native/OpenSSH fixture only.
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const base="/api/v1/accounts/rotation-";
async function finished(api,admin,id){for(let n=0;n<450;n++){const run=await api("GET",base+"runs/"+id,undefined,admin);if(!["queued","running"].includes(run.state))return run;await delay(100)}throw Error("Rotation retry timed out")}
async function verifySSH(api,admin,id){const job=await api("POST","/api/v1/ops/jobs",{asset_id:id,command:"printf rotation_retry_ssh_ok",timeout_seconds:15,request_id:randomUUID()},admin,201);for(let n=0;n<200;n++){const r=await api("GET","/api/v1/ops/jobs/"+job.id,undefined,admin);if(r.state==="succeeded"&&r.stdout==="rotation_retry_ssh_ok")return;if(["failed","denied","interrupted"].includes(r.state))throw Error("SSH after retry failed");await delay(100)}throw Error("SSH after retry timed out")}

export async function verifyRotationRetry({page,context,expect,api,admin,target,output,run,runInput,owner,sshHost,fingerprint,operator,report}){
 const name="Native selective retry",makeAsset=async label=>api("POST","/api/v1/assets",{name:label,host:sshHost,port:22,username:"rotationha",password:"synthetic-keyhost-password-233",host_key_fingerprint:fingerprint},admin,201);
 const bad=await makeAsset("Retry SSH account"),alias=await makeAsset("Retry SSH alias");
 const readAsset=async id=>{const rows=await api("GET","/api/v1/assets",undefined,admin);const found=rows.find(row=>row.id===id);if(!found)throw Error("Retry asset is absent from authoritative inventory");return found};
 const plan=await api("POST",base+"plans",{name,kind:"manual",targets:[{account_id:target.id},{account_id:bad.id},{account_id:alias.id}]},admin,201);
 const sudo=async enabled=>run("docker",["exec",sshHost,"sh","-ceu",enabled?"printf '%s\\n' 'rotationha ALL=(root) NOPASSWD: /usr/sbin/chpasswd' >>/etc/sudoers.d/qa-password-rotation":"sed -i '/^rotationha /d' /etc/sudoers.d/qa-password-rotation"]);
 const parents=[],children=[];
 try{
  for(const bulk of [false,true]){
   report.rotationRetryStep=bulk?"bulk_source":"single_source";
   await sudo(false);
   const submitted=await api("POST",base+`plans/${plan.id}/runs`,{request_id:randomUUID()},admin,202),parent=await finished(api,admin,submitted.id);
   if(parent.state!=="partial"||parent.items.find(i=>i.account_id===target.id)?.state!=="succeeded"||parent.items.filter(i=>i.state==="failed").length!==2)throw Error("Retry fixture did not produce independent success and linked failures");
   const good=await readAsset(target.id),goodRevision=good.credential_revision;
   if(!Number.isSafeInteger(goodRevision)||goodRevision<1)throw Error("Successful credential has no authoritative revision");
   await sudo(true);
   await page.reload();await page.getByRole("row").filter({hasText:name}).getByRole("button",{name:"Latest result",exact:true}).click();
   const detail=page.getByRole("dialog",{name:"Rotation results",exact:true});
   if(bulk)await detail.getByRole("button",{name:"Retry unsuccessful accounts",exact:true}).click();
   else await detail.getByRole("row").filter({hasText:alias.name}).getByRole("button",{name:"Retry this account",exact:true}).click();
   const confirmation=page.getByRole("dialog",{name:"Retry unsuccessful accounts",exact:true});await expect(confirmation).toContainText(`revision ${plan.revision}`);
   const [response]=await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname===base+`runs/${parent.id}/retry`&&r.request().method()==="POST"),confirmation.getByRole("button",{name:"Submit retry",exact:true}).click()]);
   if(response.status()!==202)throw Error("Browser retry submission failed");const input=response.request().postDataJSON(),created=await response.json(),child=await finished(api,admin,created.id);
   if(child.state!=="succeeded"||child.parent_run_id!==parent.id||child.items.length!==2||child.items.some(i=>i.account_id===target.id||!i.source_item_id))throw Error("Retry did not isolate unsuccessful aliases");
   await expect(detail.getByRole("status")).toHaveText("Succeeded",{timeout:45000});
   const after=await readAsset(target.id);if(after.credential_revision!==goodRevision)throw Error("Retry changed an already successful credential");
   const endpoint=new URL(base+`runs/${parent.id}/retry`,page.url()).href;
   const replay=await context.request.post(endpoint,{data:input});if(replay.status()!==202||(await replay.json()).id!==child.id)throw Error("Retry request replay created another run");
   await api("POST",base+`runs/${parent.id}/retry`,{...input,request_id:randomUUID()},admin,409);
   await api("POST",base+`runs/${parent.id}/retry`,input,await operator(),403);
   report.rotationRetryStep=bulk?"bulk_cli":"single_cli";
   const cliArgs=["account","rotation","retry",parent.id,"--plan-revision",String(plan.revision),"--request-id",input.request_id,...(input.item_ids?["--items",input.item_ids.join(",")]:[]),"--wait"];
   let foreignRejected=false;
   try{await run("docker",["exec",owner,"sh","-ceu",'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 exec /tmp/controller/jms "$@"',"qa-retry-cli",...cliArgs])}catch(error){foreignRejected=String(error.stderr||"").includes("SSH job API: conflict")}
   if(!foreignRejected)throw Error("Another platform actor borrowed a retry receipt");
   // Pass the same platform user's capability through a pipe, never argv/files.
   const cli=JSON.parse((await runInput("docker",["exec","-i",owner,"sh","-ceu",'IFS= read -r JMS_TOKEN; export JMS_TOKEN; JMS_SERVER_URL=http://127.0.0.1:8080 exec /tmp/controller/jms "$@"',"qa-retry-cli",...cliArgs],admin+"\n")).stdout);
   if(cli.id!==child.id||cli.parent_run_id!==parent.id)throw Error("CLI retry replay differs from Web");
   await verifySSH(api,admin,bad.id);await verifySSH(api,admin,alias.id);await verifySSH(api,admin,target.id);
   parents.push(parent.id);children.push(child.id);
   if(bulk){
    await detail.getByRole("button",{name:parent.id,exact:true}).click();await detail.screenshot({path:resolve(output,"rotation-retry.en.png")});
    await detail.getByRole("row").filter({hasText:bad.name}).getByRole("button",{name:"Open retry",exact:true}).click();
    await page.getByRole("button",{name:"中文",exact:true}).click();await page.setViewportSize({width:390,height:844});
    const chinese=page.getByRole("dialog",{name:"改密结果",exact:true});
    if(!await chinese.evaluate(el=>el.scrollWidth<=el.clientWidth+1)||!await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1))throw Error("Retry detail overflows narrow viewport");
    await chinese.screenshot({path:resolve(output,"rotation-retry.zh.png")});await chinese.getByRole("button",{name:"关闭",exact:true}).click();await page.getByRole("button",{name:"EN",exact:true}).click();await page.setViewportSize({width:1280,height:900});
   }else await detail.getByRole("button",{name:"Close",exact:true}).click();
  }
 }finally{await sudo(false);await sudo(true)}
 report.rotationRetryStep="complete";
 return {planID:plan.id,parentRunIDs:parents,retryRunIDs:children,selectedAliasExpansion:true,bulkRetry:true,successfulCredentialUnchanged:true,realSSH:true,webAndCLIReplay:true,crossActorReceiptRefused:true,duplicateAttemptRefused:true,nonAdminDenied:true,languages:["en","zh-CN"],mobileWidth:390};
}

export async function verifyRotationRetryAfterRestart({api,admin,proof}){
 for(let n=0;n<proof.parentRunIDs.length;n++){
  const parent=await api("GET",base+"runs/"+proof.parentRunIDs[n],undefined,admin),child=await api("GET",base+"runs/"+proof.retryRunIDs[n],undefined,admin);
  if(child.state!=="succeeded"||child.parent_run_id!==parent.id||parent.items.filter(i=>i.retry_run_id===child.id).length!==2)throw Error("Restart lost retry lineage");
 }
 return {restartLineagePreserved:true,encryptedBackupRestore:true};
}
