import { randomUUID } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { setTimeout as delay } from "node:timers/promises";

const base="/api/v1/settings/replay-storage";
async function stored(api,admin,id){for(let attempt=0;attempt<100;attempt++){const r=await api("GET",`${base}/records/terminal/${id}`,undefined,admin);if(r.status==="stored")return r;if(r.status==="failed")throw Error("Replay archive exhausted automatic retries");await delay(150);}throw Error("Replay archive did not complete");}
async function replay(url,admin,id){const response=await fetch(`${url}/api/v1/sessions/${id}/replay`,{headers:{Authorization:"Bearer "+admin},signal:AbortSignal.timeout(15000)});if(response.status!==200)throw Error("Authorized archived replay was unavailable");const body=gunzipSync(Buffer.from(await response.arrayBuffer())).toString("utf8"),header=JSON.parse(body.split("\n")[0]);if(header.version!==2 || header.env.JMS_SESSION_ID!==id)throw Error("Archived asciinema identity differs");return body;}

// Reuses the existing owned OpenSSH fixture and the runner's one restart. No
// containers, volumes, images, background processes or extra reports are added.
export async function verifyReplayStorage({api,admin,certificateFixture,run,runInput,owner,sshHost,url,report}){
  const initial=await api("GET",base,undefined,admin),directory="replayqa-"+randomUUID();
  const input={provider:"sftp",enabled:true,prefix:"recordings",sftp_asset_id:certificateFixture.asset.id,sftp_directory:directory,revision:initial.config.revision,request_id:randomUUID()};
  const config=await api("PUT",base,input,admin),repeated=await api("PUT",base,input,admin);if(JSON.stringify(config)!==JSON.stringify(repeated))throw Error("Storage configuration retry changed revision");
  const cli=JSON.parse((await run("docker",["exec",owner,"sh","-ceu",'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/controller/jms replay-storage settings'])).stdout);if(cli.config.provider!=="sftp" || cli.config.revision!==config.revision)throw Error("Native CLI replay settings differ");
  const session=await api("POST","/api/v1/sessions",{asset_id:certificateFixture.asset.id,cols:80,rows:24},admin,201);await api("DELETE",`/api/v1/sessions/${session.session_id}`,undefined,admin,204);
  const queueInput={request_id:randomUUID()},path=`${base}/records/terminal/${session.session_id}`;
  const queued=await api("POST",path+"/archive",queueInput,admin);if(JSON.stringify(queued)!==JSON.stringify(await api("POST",path+"/archive",queueInput,admin)))throw Error("Historical queue retry changed receipt");
  await stored(api,admin,session.session_id);
  const verifyInput={request_id:randomUUID()},verified=await api("POST",path+"/verify",verifyInput,admin);if(JSON.stringify(verified)!==JSON.stringify(await api("POST",path+"/verify",verifyInput,admin)))throw Error("Remote verification retry changed receipt");
  const evictInput={request_id:randomUUID()},evicted=await api("POST",path+"/evict",evictInput,admin);if(!evicted.local_evicted_at || JSON.stringify(evicted)!==JSON.stringify(await api("POST",path+"/evict",evictInput,admin)))throw Error("Local eviction was not idempotent");
  await run("docker",["exec",owner,"sh","-ceu",'test ! -e "/data/sessions/$1.json.gz.enc"; test -f /data/sessions/index.jsonl',"sh",session.session_id]);
  await replay(url,admin,session.session_id);
  await runInput("docker",["exec","-i",sshHost,"sh","-ceu","id -u remoteqa_store233 >/dev/null 2>&1 || useradd -m -s /bin/bash remoteqa_store233; chpasswd"],"remoteqa_store233:synthetic-replay-storage-password-233\n");
  const storageAsset=await api("POST","/api/v1/assets",{name:"Native replay password storage",host:certificateFixture.asset.host,port:certificateFixture.asset.port,username:"remoteqa_store233",password:"synthetic-replay-storage-password-233",host_key_fingerprint:certificateFixture.asset.host_key_fingerprint},admin,201);
  const passwordConfig=await api("PUT",base,{provider:"sftp",enabled:true,prefix:"recordings",sftp_asset_id:storageAsset.id,sftp_directory:directory,revision:config.revision,request_id:randomUUID()},admin);
  const passwordSession=await api("POST","/api/v1/sessions",{asset_id:certificateFixture.asset.id,cols:80,rows:24},admin,201);await api("DELETE",`/api/v1/sessions/${passwordSession.session_id}`,undefined,admin,204);await stored(api,admin,passwordSession.session_id);
  await api("POST",`/api/v1/assets/${storageAsset.id}/password-rotation`,undefined,admin);const afterRotation=await api("GET",base,undefined,admin);if(afterRotation.config.revision!==passwordConfig.revision || afterRotation.config.sftp_target!==passwordConfig.sftp_target)throw Error("Password rotation invalidated storage locator");
  const passwordPath=`${base}/records/terminal/${passwordSession.session_id}`;await api("POST",passwordPath+"/verify",{request_id:randomUUID()},admin);await api("POST",passwordPath+"/evict",{request_id:randomUUID()},admin);await replay(url,admin,passwordSession.session_id);
  report.replayStorage={sessionID:session.session_id,provider:"sftp",nativeCLI:true,certificateAuthenticatedStorage:true,realSSHAndSFTP:true,configurationReplay:true,queueReplay:true,verifyReplay:true,evictionReplay:true,wholeObjectReadback:true,remoteOnlyAuthorizedReplay:true,localAuditIndexPreserved:true};
  report.replayStorage.passwordRotationKeepsHistoricalLocator=true;
  return {sessionID:session.session_id,passwordSessionID:passwordSession.session_id,config:passwordConfig,queueInput,queued};
}
export async function verifyReplayStorageRestart({api,admin,fixture,url,report}){
  const current=await api("GET",base,undefined,admin);if(current.config.revision!==fixture.config.revision || current.config.sftp_target!==fixture.config.sftp_target)throw Error("Restart lost storage locator");
  const repeated=await api("POST",`${base}/records/terminal/${fixture.sessionID}/archive`,fixture.queueInput,admin);if(JSON.stringify(repeated)!==JSON.stringify(fixture.queued))throw Error("Restart lost archive receipt");await replay(url,admin,fixture.sessionID);await replay(url,admin,fixture.passwordSessionID);report.replayStorage.restartAndRemoteOnlyReplay=true;
}
export async function verifyReplayStorageBrowser({page,expect,url,api,admin,report}){
  const sessions=await api("GET","/api/v1/sessions?offset=0&limit=200",undefined,admin),latest=sessions.results.filter(r=>r.asset_id===report.sshCertificates.assetID && r.status==="ended").sort((a,b)=>Date.parse(b.started_at)-Date.parse(a.started_at))[0];
  if(!latest || latest.session_id===report.replayStorage.sessionID)throw Error("Native Web SSH recording was not finalized");await stored(api,admin,latest.session_id);await api("POST",`${base}/records/terminal/${latest.session_id}/evict`,{request_id:randomUUID()},admin);const body=await replay(url,admin,latest.session_id),output=body.split("\n").slice(1).filter(Boolean).map(line=>JSON.parse(line)).filter(event=>event[1]==="o").map(event=>event[2]).join("");if(!output.includes("certificate-web-ok"))throw Error("Remote Web SSH recording lost terminal output");report.replayStorage.webSSHRecordingRoundTrip=true;
  await page.goto(url+"/console/replay-storage");const english=page.getByRole("button",{name:"EN",exact:true});if(await english.count())await english.click();await expect(page.getByRole("heading",{name:"Replay storage",exact:true})).toBeVisible();
  const card=page.getByRole("article",{name:report.replayStorage.sessionID,exact:true});await expect(card).toContainText("Removed after remote verification");const verified=page.waitForResponse(r=>r.request().method()==="POST" && new URL(r.url()).pathname.endsWith("/verify"));await card.getByRole("button",{name:"Verify remote copy",exact:true}).click();if((await verified).status()!==200)throw Error("Browser remote verification failed");
  await page.setViewportSize({width:390,height:844});await page.getByRole("button",{name:"中文",exact:true}).click();await expect(page.getByRole("heading",{name:"录像存储",exact:true})).toBeVisible();if(!await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth))throw Error("Replay storage page overflows mobile viewport");await page.getByRole("button",{name:"EN",exact:true}).click();await page.setViewportSize({width:1280,height:900});report.replayStorage.bilingualMobileBrowser=true;
  // The parent runner later destroys its owned SSH/container data and retains
  // only its existing compact report; external storage receives no Delete API.
}
