import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { writeFile, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
const execute = promisify(execFile);
const base = process.env.JMS_ROTATION_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_ROTATION_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base)) throw Error("Rotation QA requires loopback isolation");
test.use({ locale:"en-US",trace:"off" });
test("rotation plans reset ordinary users through a privileged account, rotate keys, deduplicate aliases, report partial failure and enforce schedules and ACL",async({browser},info)=>{
 test.setTimeout(240_000);
 const api=await request.newContext({baseURL:base}),context=await browser.newContext({locale:"en-US",viewport:{width:1440,height:1080}}),page=await context.newPage();
 const errors:string[]=[];page.on("pageerror",(e)=>errors.push(e.message));
 const stamp=Date.now(),users=["a","k","f","c"].map((v)=>`managedqa_p${v}${stamp.toString(36)}`),names=["Password","Key","Denied self reset","Alias","Collector"].map((v)=>`Rotation ${v} ${stamp}`);
 const assets:string[]=[],plans:string[]=[],createdUsers:string[]=[],roles:string[]=[],policies:string[]=[];
 const retain=process.env.JMS_ROTATION_QA_RETAIN==="true",initial="synthetic-rotation-initial-password-233";
 let hostName="",owner="",token="",operatorID="",succeeded=false;
 const verifyOwner=async()=>{const labels=JSON.parse((await execute("docker",["inspect","--format","{{json .Config.Labels}}",hostName])).stdout);expect(labels["com.jumpserver233.qa.owner"]).toBe(owner);};
 const cli=(args:string[])=>execute("go",["run","./cmd/jms",...args],{cwd:fileURLToPath(new URL("../../server",import.meta.url)),timeout:90_000,env:{...process.env,JMS_SERVER_URL:base,JMS_TOKEN:token,JMS_ORG_ID:"",JMS_ACCOUNT:"",JMS_ACCESS_KEY_ID:"",JMS_ACCESS_KEY_SECRET:""}});
 const planInput=(name:string,targets:any[])=>({name,kind:"manual",enabled:false,only_due:false,revision:0,targets});
 const finish=async(id:string)=>{await expect.poll(async()=>{const run=await(await api.get("/api/v1/accounts/rotation-runs/"+id)).json();return run.state;},{timeout:90_000,intervals:[500,1000]}).not.toMatch(/^(queued|running)$/);return(await api.get("/api/v1/accounts/rotation-runs/"+id)).json();};
 try{
  const admin={username:process.env.JMS_ROTATION_QA_USERNAME||"e2e.admin",password:process.env.JMS_ROTATION_QA_PASSWORD||"synthetic-e2e-admin-password-2468"};
  let login=await api.post("/api/v1/authentication/auth/",{data:admin});if(!login.ok()){await api.post("/api/v1/authentication/bootstrap",{data:admin});login=await api.post("/api/v1/authentication/auth/",{data:admin});}
  expect(login.ok()).toBe(true);token=(await login.json()).access_token;await context.addCookies((await api.storageState()).cookies);
  const host=await(await api.get(process.env.JMS_ROTATION_QA_FIXTURE_URL||"http://127.0.0.1:12242/health")).json();hostName=host.container_name;owner=host.owner;
  expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);expect(owner===hostName||/^jumpserver233-e2e-/.test(owner)).toBe(true);await verifyOwner();
  for(const user of users){
   expect(user).toMatch(/^managedqa_p[akfc][a-z0-9]+$/);
   await execute("docker",["exec",hostName,"sh","-ceu",'useradd -m -s /bin/bash "$1"; printf "%s:%s\\n" "$1" "$2" | chpasswd; test ! -f "/etc/sudoers.d/$1"',"qa-create",user,initial]);createdUsers.push(user);
  }
  await execute("docker",["exec",hostName,"sh","-ceu",'printf "%s ALL=(root) NOPASSWD: /usr/sbin/chpasswd\\n" "$1" > "/etc/sudoers.d/$1"; chmod 0440 "/etc/sudoers.d/$1"',"qa-privileged-collector",users[3]]);
  for(let i=0;i<5;i++){
   const username=i===4?users[3]:i===3?users[0]:users[i];
   const r=await api.post("/api/v1/assets",{data:{name:names[i],host:process.env.JMS_ROTATION_QA_SSH_HOST||"127.0.0.1",port:Number(host.address.split(":").at(-1)),username,password:initial,host_key_fingerprint:host.fingerprint}});
   const createdAsset=await r.json();expect(r.status(),createdAsset.detail||"create rotation fixture").toBe(201);const id=createdAsset.id;assets.push(id);
   const current=await(await api.get(`/api/v1/assets/${id}/accounts/${id}`)).json();
   expect((await api.put(`/api/v1/assets/${id}/accounts/${id}`,{data:{version:current.version,password_rotation_enabled:false,key_rotation_enabled:false}})).status()).toBe(200);
  }
  const keyAsset=await(await api.get(`/api/v1/assets/${assets[1]}/accounts/${assets[1]}`)).json();
  expect((await api.post(`/api/v1/assets/${assets[1]}/ssh-key-rotation`,{data:{request_id:randomUUID(),expected_revision:keyAsset.credential_revision}})).status()).toBe(200);
  await page.goto(ui+"/console/rotation-plans");await expect(page.getByRole("heading",{name:"Credential rotation plans",exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Create plan",exact:true}).click();
  const editor=page.getByRole("dialog",{name:"Create plan",exact:true}),planName=`Production SSH rotation ${stamp}`;
  await editor.getByLabel("Plan name",{exact:true}).fill(planName);
  await editor.getByLabel("Search host or username",{exact:true}).fill(String(stamp));await editor.getByRole("button",{name:"Search",exact:true}).click();
  for(const i of [0,1,2,3])await editor.getByRole("checkbox",{name:`${names[i]} · ${i===3?users[0]:users[i]}`,exact:true}).check();
  const passwordRow=editor.getByRole("listitem").filter({has:page.getByText(`${names[0]} · ${users[0]}`,{exact:true})});
  await passwordRow.getByRole("button",{name:"Choose privileged account",exact:true}).click();
  const chooser=page.getByRole("dialog",{name:"Choose privileged account",exact:true});
  await chooser.getByRole("button",{name:`${names[4]} · ${users[3]}`,exact:true}).click();
  const savedResponse=page.waitForResponse((r)=>r.url().endsWith("/api/v1/accounts/rotation-plans")&&r.request().method()==="POST");
  await editor.getByRole("button",{name:"Save plan",exact:true}).click();const saved=await savedResponse;expect(saved.status()).toBe(201);
  await expect(page.getByRole("row").filter({hasText:planName})).toBeVisible();
  const savedPage=await(await api.get("/api/v1/accounts/rotation-plans?limit=100")).json();const savedPlan=savedPage.results.find((v:any)=>v.name===planName);expect(savedPlan).toBeTruthy();
  const plan=await(await api.get("/api/v1/accounts/rotation-plans/"+savedPlan.id)).json();plans.push(plan.id);
  expect(plan.target_count).toBe(4);expect(JSON.stringify(plan)).not.toContain(initial);
  const row=page.getByRole("row").filter({hasText:planName});await row.getByRole("button",{name:"Rotate now",exact:true}).click();
  const confirmation=page.getByRole("dialog",{name:"Start credential rotation",exact:true});
  const runResponse=page.waitForResponse((r)=>r.url().endsWith(`/rotation-plans/${plan.id}/runs`)&&r.request().method()==="POST");
  await confirmation.getByRole("button",{name:"Rotate now",exact:true}).click();const runReply=await runResponse;expect(runReply.status()).toBe(202);const submitted=await runReply.json();
  const result=await finish(submitted.id);expect(result.state).toBe("partial");expect(result.items.filter((v:any)=>v.state==="succeeded")).toHaveLength(3);expect(result.items.filter((v:any)=>v.state==="failed")).toHaveLength(1);
  expect(result.items.find((v:any)=>v.account_id===assets[3]).linked_to).toBeTruthy();
  const detail=page.getByRole("dialog",{name:"Rotation results",exact:true});await expect(detail.getByRole("status")).toHaveText("Partially succeeded",{timeout:90_000});
  for(const i of [0,1,3])expect(JSON.parse((await cli(["exec",assets[i],"--json","--","id -un"])).stdout).stdout.trim()).toBe(i===3?users[0]:users[i]);
  const before=await(await api.get(`/api/v1/assets/${assets[0]}/accounts/${assets[0]}`)).json();
  try{await cli(["account","rotation","run",plan.id,"--request-id",submitted.request_id,"--wait"]);throw Error("partial result should exit nonzero");}catch(e:any){expect(e.code).toBe(1);expect(JSON.parse(e.stdout).id).toBe(submitted.id);}
  const after=await(await api.get(`/api/v1/assets/${assets[0]}/accounts/${assets[0]}`)).json();expect(after.credential_revision).toBe(before.credential_revision);
  const downloadEvent=page.waitForEvent("download");await detail.getByRole("button",{name:"Export metadata CSV",exact:true}).click();const download=await downloadEvent;const csv=await readFile((await download.path())!,"utf8");expect(csv).not.toContain(initial);expect(csv).not.toContain("PRIVATE KEY");expect(csv).toContain(assets[0]);
  await detail.getByRole("button",{name:"Close",exact:true}).click();
  await row.getByRole("button",{name:"Edit plan",exact:true}).click();const edit=page.getByRole("dialog",{name:"Edit plan",exact:true});
  await edit.getByLabel("Schedule",{exact:true}).selectOption("interval");await edit.getByLabel("Interval in hours",{exact:true}).fill("168");await edit.getByLabel("Scheduled runs rotate only credentials older than this interval",{exact:true}).check();await edit.getByLabel("Enable scheduling with the current owner's permissions",{exact:true}).check();
  const updateResponse=page.waitForResponse((r)=>r.url().endsWith("/rotation-plans/"+plan.id)&&r.request().method()==="PUT");await edit.getByRole("button",{name:"Save plan",exact:true}).click();expect((await updateResponse).status()).toBe(200);
  let scheduled:any;
  await expect.poll(async()=>{const r=await(await api.get("/api/v1/accounts/rotation-runs?plan_id="+plan.id)).json();scheduled=r.results.find((v:any)=>v.scheduled);return scheduled?.state;},{timeout:20_000,intervals:[500,1000]}).toBe("succeeded");
  const skipped=await(await api.get("/api/v1/accounts/rotation-runs/"+scheduled.id)).json();expect(skipped.items.every((v:any)=>v.state==="not_due")).toBe(true);
  const periodic=await(await api.get("/api/v1/accounts/rotation-plans/"+plan.id)).json();expect(Date.parse(periodic.next_run)).toBeGreaterThan(Date.now()+6*24*3600_000);
  expect((await api.put("/api/v1/accounts/rotation-plans/"+plan.id,{data:{...planInput(planName,periodic.targets),kind:"interval",interval_hours:168,only_due:true,revision:periodic.revision}})).status()).toBe(200);
  const operator={username:`rotation.operator.${stamp}`,password:"synthetic-rotation-platform-password-233"};
  const created=await api.post("/api/v1/users",{data:{...operator,role:"operator"}});expect(created.status()).toBe(201);operatorID=(await created.json()).id;
  const role=await api.post("/api/v1/rbac/roles",{data:{name:`Rotation operator ${stamp}`,permissions:["accounts.rotation.view","accounts.rotation.manage","accounts.rotation.execute","assets.rotate","assets.view_all"]}});expect(role.status()).toBe(201);const roleID=(await role.json()).id;roles.push(roleID);
  expect((await api.put("/api/v1/rbac/bindings",{data:{subject_type:"user",subject_id:operatorID,role_ids:[roleID]}})).status()).toBe(200);
  const guest=await browser.newContext({locale:"en-US"});
  try{
   expect((await guest.request.post(base+"/api/v1/authentication/auth/",{data:operator})).ok()).toBe(true);
   const p=await guest.request.post(base+"/api/v1/accounts/rotation-plans",{data:planInput(`Restricted ${stamp}`,[{account_id:assets[0],collector_id:assets[4]}])});expect(p.status()).toBe(201);const own=await p.json();plans.push(own.id);
   expect((await guest.request.post(base+"/api/v1/accounts/rotation-plans/"+own.id+"/runs",{data:{request_id:randomUUID()}})).status()).toBe(403);
   const denial=await api.post("/api/v1/access-policies",{data:{name:`Deny rotation ${stamp}`,kind:"method",user_id:operatorID,methods:["credential_rotation"],action:"deny",enabled:true,priority:50,timezone:"UTC"}});expect(denial.status()).toBe(201);policies.push((await denial.json()).id);
   expect((await guest.request.post(base+`/api/v1/assets/${assets[0]}/password-rotation`)).status()).toBe(403);
   const plain=await guest.request.post(base+"/api/v1/accounts/rotation-plans",{data:planInput(`Policy denied ${stamp}`,[{account_id:assets[2]}])});expect(plain.status()).toBe(201);const ownPlain=await plain.json();plans.push(ownPlain.id);
   const deniedRun=await guest.request.post(base+`/api/v1/accounts/rotation-plans/${ownPlain.id}/runs`,{data:{request_id:randomUUID()}});expect(deniedRun.status()).toBe(202);
   const denied=await finish((await deniedRun.json()).id);expect(denied.items[0].state).toBe("denied");
   const viewer=await api.post("/api/v1/rbac/roles",{data:{name:`Rotation view only ${stamp}`,permissions:["accounts.rotation.view","assets.view_all"]}});const viewerID=(await viewer.json()).id;roles.push(viewerID);
   const binding=await(await api.get("/api/v1/rbac/bindings")).json();const old=binding.find((v:any)=>v.subject_id===operatorID);
   expect((await api.put("/api/v1/rbac/bindings",{data:{subject_type:"user",subject_id:operatorID,role_ids:[viewerID],revision:old.revision}})).status()).toBe(200);
   const guestPage=await guest.newPage();await guestPage.goto(ui+"/console/rotation-plans");await expect(guestPage.getByRole("heading",{name:"Credential rotation plans",exact:true})).toBeVisible();await expect(guestPage.getByRole("button",{name:"Create plan",exact:true})).toHaveCount(0);await expect(guestPage.getByRole("button",{name:"Rotate now",exact:true})).toHaveCount(0);
  }finally{await guest.close();}
  await page.getByRole("button",{name:"Refresh",exact:true}).click();await page.screenshot({path:info.outputPath("rotation-plans.en.png"),fullPage:true});
  await page.getByRole("button",{name:"中文",exact:true}).click();await expect(page.getByRole("heading",{name:"账号改密计划",exact:true})).toBeVisible();await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.screenshot({path:info.outputPath("rotation-plans.zh-CN.png"),fullPage:true});
  expect(errors).toEqual([]);await writeFile(info.outputPath("rotation-result.json"),JSON.stringify({assets,names,users,plans,run:result.id,fixture:hostName,realSSH:true,privilegedReset:true,keyRotation:true,aliasDedup:true,partialFailure:true,weeklyDueCheck:true,acl:true,retained:retain}));succeeded=true;
 }finally{
  if(!retain||!succeeded){
   for(const id of policies)await api.delete("/api/v1/access-policies/"+id);
   for(const id of plans){const r=await api.get("/api/v1/accounts/rotation-plans/"+id);if(r.ok()){const p=await r.json();if(p.enabled)await api.put("/api/v1/accounts/rotation-plans/"+id,{data:{...planInput(p.name,p.targets),kind:p.kind,run_at:p.run_at,interval_hours:p.interval_hours,only_due:p.only_due,revision:p.revision}});const latest=await(await api.get("/api/v1/accounts/rotation-plans/"+id)).json();await api.delete("/api/v1/accounts/rotation-plans/"+id+"?revision="+latest.revision);}}
   for(const id of assets)await api.delete("/api/v1/assets/"+id);if(operatorID)await api.delete("/api/v1/users/"+operatorID);for(const id of roles)await api.delete("/api/v1/rbac/roles/"+id);
   if(createdUsers.length){await verifyOwner();for(const user of createdUsers)await execute("docker",["exec",hostName,"sh","-ceu",'uid=$(id -u "$1"); test "$uid" -ge 1000; rm -f "/etc/sudoers.d/$1"; userdel "$1"',"qa-remove",user]);}
  }
  await api.post("/api/v1/authentication/expire-session/",{headers:{Origin:ui}}).catch(()=>{});
  if(token)await api.post("/api/v1/authentication/expire-session/",{headers:{Authorization:`Bearer ${token}`,Origin:ui}}).catch(()=>{});
  await context.close();await api.dispose();
 }
});
