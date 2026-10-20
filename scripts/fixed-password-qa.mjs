// Runs only against the owned native package fixture. No secret enters reports.
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const base = "/api/v1/accounts/rotation-";
function publicOnly(value, secrets) {
 const text=JSON.stringify(value);
 if(secrets.some(secret=>text.includes(secret))||text.includes('"fixed_secret_id"')||text.includes('"fixed_password"'))throw Error("Protected fixed password escaped a public response");
}
async function finished(api,admin,id){for(let n=0;n<300;n++){const run=await api("GET",base+"runs/"+id,undefined,admin);if(!["queued","running"].includes(run.state))return run;await delay(100)}throw Error("Fixed password run timed out")}
async function ssh(api,admin,target){const job=await api("POST","/api/v1/ops/jobs",{asset_id:target,command:"printf fixed_password_ssh_ok",timeout_seconds:15,request_id:randomUUID()},admin,201);for(let n=0;n<200;n++){const value=await api("GET","/api/v1/ops/jobs/"+job.id,undefined,admin);if(value.state==="succeeded"&&value.stdout==="fixed_password_ssh_ok")return;if(["failed","denied","interrupted"].includes(value.state))throw Error("SSH after fixed password failed");await delay(100)}throw Error("Fixed password SSH timed out")}

export async function verifyFixedPassword({page,context,expect,api,admin,target,output,runInput,owner}){
 const name="Native protected fixed password",secret="Ab2!".repeat(16),other="Cd3#".repeat(16);
 await page.getByRole("button",{name:"Create plan",exact:true}).click();
 const editor=page.getByRole("dialog",{name:"Create plan",exact:true});
 await editor.getByLabel("Plan name",{exact:true}).fill(name);await editor.getByLabel("Password source",{exact:true}).selectOption("fixed");
 await editor.getByLabel("Fixed password (write only)",{exact:true}).fill(secret);
 await editor.getByLabel("Search host or username",{exact:true}).fill(target.name);await editor.getByRole("button",{name:"Search",exact:true}).click();
 await editor.getByRole("checkbox",{name:`${target.name} · rotationqa`,exact:true}).check();
 const [saved]=await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname===base+"plans"&&r.request().method()==="POST"),editor.getByRole("button",{name:"Save plan",exact:true}).click()]);
 if(saved.status()!==201)throw Error("Fixed password browser save failed");const input=saved.request().postDataJSON(),plan=await saved.json();publicOnly(plan,[secret,other]);
 if(plan.password_mode!=="fixed"||plan.save_request_id!==input.request_id)throw Error("Fixed password metadata receipt differs");
 const endpoint=new URL(base+"plans",page.url()).href;
 const retry=await context.request.post(endpoint,{data:input});if(retry.status()!==201||(await retry.json()).id!==plan.id)throw Error("Fixed password save replay duplicated its plan");
 const conflict=await context.request.post(endpoint,{data:{...input,fixed_password:other}});if(conflict.status()!==409)throw Error("Fixed password request input was not bound");
 for(const path of [base+"plans/"+plan.id,base+"plans",base+"audit"])publicOnly(await api("GET",path,undefined,admin),[secret,other]);
 const row=page.getByRole("row").filter({hasText:name});await row.getByRole("button",{name:"Rotate now",exact:true}).click();
 const confirmation=page.getByRole("dialog",{name:"Start credential rotation",exact:true});
 const [reply]=await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname===base+`plans/${plan.id}/runs`&&r.request().method()==="POST"),confirmation.getByRole("button",{name:"Rotate now",exact:true}).click()]);
 if(reply.status()!==202)throw Error("Fixed password browser run failed");const submitted=await reply.json(),completed=await finished(api,admin,submitted.id);publicOnly(completed,[secret,other]);
 if(completed.state!=="succeeded"||completed.password_mode!=="fixed")throw Error("Fixed password SSH rotation failed");await ssh(api,admin,target.id);
 const detail=page.getByRole("dialog",{name:"Rotation results",exact:true});await expect(detail.getByRole("status")).toHaveText("Succeeded",{timeout:45000});await detail.getByRole("button",{name:"Close",exact:true}).click();
 await row.getByRole("button",{name:"Edit plan",exact:true}).click();const edit=page.getByRole("dialog",{name:"Edit plan",exact:true});await expect(edit.getByLabel("Fixed password (write only)",{exact:true})).toHaveValue("");
 const [kept]=await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname===base+"plans/"+plan.id&&r.request().method()==="PUT"),edit.getByRole("button",{name:"Save plan",exact:true}).click()]);
 if(kept.status()!==200||kept.request().postDataJSON().fixed_password!==undefined)throw Error("Blank fixed input did not preserve the protected value");publicOnly(await kept.json(),[secret,other]);
 await row.getByRole("button",{name:"Edit plan",exact:true}).click();await edit.screenshot({path:resolve(output,"fixed-password.en.png")});await edit.getByRole("button",{name:"Close",exact:true}).click();
 await page.getByRole("button",{name:"中文",exact:true}).click();await page.setViewportSize({width:390,height:844});await page.getByRole("row").filter({hasText:name}).getByRole("button",{name:"编辑计划",exact:true}).click();
 const chinese=page.getByRole("dialog",{name:"编辑计划",exact:true});await expect(chinese.getByLabel("固定密码（只写）",{exact:true})).toHaveValue("");if(!await chinese.evaluate(el=>el.scrollWidth<=el.clientWidth+1)||!await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1))throw Error("Fixed password controls overflow mobile viewport");await chinese.screenshot({path:resolve(output,"fixed-password.zh.png")});await chinese.getByRole("button",{name:"关闭",exact:true}).click();
 await page.getByRole("button",{name:"EN",exact:true}).click();await page.setViewportSize({width:1280,height:900});
 const metadata={name:"Protected CLI fixed plan",kind:"manual",password_mode:"fixed",targets:[{account_id:target.id}]};
 await runInput("docker",["exec","-i",owner,"sh","-ceu","umask 077; cat >/tmp/fixed-plan.json"],JSON.stringify(metadata));
 const request=randomUUID(),args=["account","rotation","create","--file","/tmp/fixed-plan.json","--request-id",request,"--fixed-password-file","-"];
 const cli=async arguments_=>JSON.parse((await runInput("docker",["exec","-i",owner,"sh","-ceu",'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 exec /tmp/controller/jms "$@"',"qa-fixed-cli",...arguments_],other)).stdout);
 const created=await cli(args),replayed=await cli(args);publicOnly(created,[secret,other]);publicOnly(replayed,[secret,other]);if(created.id!==replayed.id||created.revision!==replayed.revision)throw Error("Protected CLI save was not idempotent");
 const generated=await api("PUT",base+"plans/"+created.id,{...metadata,password_mode:"generated",revision:created.revision,request_id:randomUUID()},admin);publicOnly(generated,[secret,other]);if(generated.password_mode!=="generated")throw Error("Clearing fixed strategy failed");
 return {planID:plan.id,runID:completed.id,targetID:target.id,writeOnlyWeb:true,publicReadsSanitized:true,saveReplay:true,changedInputRejected:true,realSSH:true,blankEditKeepsSecret:true,protectedCLIStdin:true,cliSaveReplay:true,clearFixedStrategy:true,languages:["en","zh-CN"],mobileWidth:390};
}

export async function verifyFixedPasswordAfterRestart({api,admin,proof}){
 const plan=await api("GET",base+"plans/"+proof.planID,undefined,admin);if(plan.password_mode!=="fixed")throw Error("Restart lost fixed plan mode");
 const submitted=await api("POST",base+`plans/${plan.id}/runs`,{request_id:randomUUID()},admin,202),completed=await finished(api,admin,submitted.id);
 if(completed.state!=="succeeded"||completed.password_mode!=="fixed")throw Error("Restart did not retain the protected fixed password");await ssh(api,admin,proof.targetID);
 return {retainedSecretExecutedAfterRestart:true,realSSHAfterRestart:true};
}
