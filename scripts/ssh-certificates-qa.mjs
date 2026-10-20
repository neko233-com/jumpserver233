import { randomUUID } from "node:crypto";

const base = "/api/v1/settings/ssh-certificates";
const issuerInput = (v, enabled) => ({name:v.name,provider:v.provider,enabled,ttl_seconds:v.ttl_seconds,public_key:v.public_key,revision:v.revision,request_id:randomUUID()});

export async function verifySSHCertificates({api,admin,run,runInput,owner,sshHost,fingerprint,url,report}) {
  const user = "remoteqa_cert233";
  await runInput("docker",["exec","-i",sshHost,"sh","-ceu",'id -u remoteqa_cert233 >/dev/null 2>&1 || useradd -m -s /bin/bash remoteqa_cert233; chpasswd'],`${user}:synthetic-certificate-fixture-password-233\n`);
  let issuer=await api("POST",base+"/issuers",{name:"Native SSH CA "+randomUUID(),provider:"builtin",enabled:true,ttl_seconds:120,request_id:randomUUID()},admin,201);
  const installTrust=async bundle=>{await runInput("docker",["exec","-i",sshHost,"sh","-ceu","cat > /run/jms-qa-ca.pub; chmod 644 /run/jms-qa-ca.pub"],bundle);};
  await installTrust(issuer.trust_bundle);
  await runInput("docker",["exec","-i",sshHost,"sh","-ceu",'cat >> /etc/ssh/sshd_config_fixture; /usr/sbin/sshd -t -f /etc/ssh/sshd_config_fixture; pid=$(cat /run/keyhost.pid); case "$pid" in ""|*[!0-9]*) exit 1;; esac; kill -HUP "$pid"'],`\nTrustedUserCAKeys /run/jms-qa-ca.pub\nMatch User ${user}\n  PasswordAuthentication no\n  AuthenticationMethods publickey\nMatch all\n`);
  const asset=await api("POST","/api/v1/assets",{name:"Native certificate SSH",host:sshHost,port:22,username:user,password:"intentionally-wrong-certificate-bootstrap",host_key_fingerprint:fingerprint},admin,201);
  const offline=await api("POST",`/api/v1/assets/${asset.id}/probe`,undefined,admin);
  if(offline.monitor.state==="online")throw Error("Certificate-only target accepted bootstrap credentials");
  const bindingInput={issuer_id:issuer.id,revision:0,request_id:randomUUID()};
  const bound=await api("PUT",`${base}/bindings/${asset.id}`,bindingInput,admin);
  const repeated=await api("PUT",`${base}/bindings/${asset.id}`,bindingInput,admin);
  if(JSON.stringify(bound)!==JSON.stringify(repeated))throw Error("Certificate binding retry changed policy");
  const probe=await api("POST",`/api/v1/assets/${asset.id}/probe`,undefined,admin);
  if(probe.monitor.state!=="online")throw Error("Native certificate monitoring did not authenticate");
  const cli=JSON.parse((await run("docker",["exec",owner,"sh","-ceu",'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/controller/jms exec "$1" --json -- printf certificate-cli-ok',"sh",asset.id])).stdout);
  if(cli.state!=="succeeded"||cli.stdout!=="certificate-cli-ok")throw Error("Native certificate CLI execution failed");
  const filePath=`/api/v1/assets/${asset.id}/files/content?path=certificate-proof.txt`;
  const transfer=async(method,body,status)=>{const r=await fetch(url+filePath,{method,headers:{Authorization:"Bearer "+admin},...(body===undefined?{}:{body}),signal:AbortSignal.timeout(10000)});if(r.status!==status)throw Error("Certificate SFTP status differs from expected");return r;};
  await transfer("PUT","certificate-sftp-ok",201);if(await(await transfer("GET",undefined,200)).text()!=="certificate-sftp-ok")throw Error("Certificate SFTP data mismatch");await transfer("DELETE",undefined,204);
  issuer=await api("POST",`${base}/issuers/${issuer.id}/rotate`,{revision:issuer.revision,request_id:randomUUID()},admin);
  const oldPublic=issuer.public_key;await installTrust(issuer.trust_bundle);
  issuer=await api("POST",`${base}/issuers/${issuer.id}/activate`,{revision:issuer.revision,request_id:randomUUID()},admin);
  if(issuer.public_key===oldPublic)throw Error("CA activation did not change signing key");
  if((await api("POST",`/api/v1/assets/${asset.id}/probe`,undefined,admin)).monitor.state!=="online")throw Error("Activated CA did not authenticate after trust distribution");
  issuer=await api("PUT",`${base}/issuers/${issuer.id}`,issuerInput(issuer,false),admin);
  if((await api("POST",`/api/v1/assets/${asset.id}/probe`,undefined,admin)).monitor.state==="online")throw Error("Disabled CA reused certificate or fallback authentication");
  issuer=await api("PUT",`${base}/issuers/${issuer.id}`,issuerInput(issuer,true),admin);
  report.sshCertificates={assetID:asset.id,issuerID:issuer.id,certificateOnlyPasswordDenied:true,monitoring:true,nativeCLI:true,realSFTP:true,twoPhaseTrustAndActivation:true,disabledIssuerFailsClosed:true,idempotentBinding:true};
  return {asset,issuer,bindingInput};
}

export async function verifySSHCertificateRestart({api,admin,fixture,report}) {
  const binding=await api("PUT",`${base}/bindings/${fixture.asset.id}`,fixture.bindingInput,admin);
  if(binding.revision!==1||(await api("POST",`/api/v1/assets/${fixture.asset.id}/probe`,undefined,admin)).monitor.state!=="online")throw Error("Certificate policy or signer lost after restart");
  report.sshCertificates.restartAndReceiptPreserved=true;
}

export async function verifySSHCertificateBrowser({page,expect,url,api,admin,report}) {
  let output="";const handler=socket=>socket.on("framereceived",event=>{if(Buffer.isBuffer(event.payload))output+=event.payload.toString("utf8");});page.on("websocket",handler);
  try{
    await page.goto(url+"/console?asset_id="+report.sshCertificates.assetID);
    const english=page.getByRole("button",{name:"English",exact:true});if(await english.count())await english.click();
    const row=page.getByRole("row").filter({hasText:"Native certificate SSH"});await row.getByRole("button",{name:"Connect",exact:true}).click();
    const terminal=page.locator(".ssh-terminal-dialog");await expect(terminal.locator(".ssh-terminal-status.connected")).toBeVisible();
    const marker="certificate-web-ok",octal=Array.from(Buffer.from(marker+"\n"),b=>"\\"+b.toString(8)).join("");await terminal.locator(".xterm-helper-textarea").pressSequentially(`printf '${octal}'`);await terminal.locator(".xterm-helper-textarea").press("Enter");
    await expect.poll(()=>output,{timeout:15000}).toContain(marker);
    let issuer=(await api("GET",base+"/issuers",undefined,admin)).find(v=>v.id===report.sshCertificates.issuerID);
    issuer=await api("PUT",`${base}/issuers/${issuer.id}`,issuerInput(issuer,false),admin);
    await terminal.locator(".xterm-helper-textarea").press("Enter");await expect(terminal.locator(".ssh-terminal-status.closed")).toBeVisible({timeout:15000});
    await api("PUT",`${base}/issuers/${issuer.id}`,issuerInput(issuer,true),admin);
    await terminal.getByRole("button",{name:"Close terminal",exact:true}).click();report.sshCertificates.livePolicyRevocation=true;
    await page.goto(url+"/console/ssh-certificates?asset_id="+report.sshCertificates.assetID);await expect(page.getByRole("heading",{name:"SSH certificates",exact:true})).toBeVisible();
    await page.setViewportSize({width:390,height:844});await page.getByRole("button",{name:"中文",exact:true}).click();await expect(page.getByRole("heading",{name:"SSH 证书",exact:true})).toBeVisible();
    if(!await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth))throw Error("Certificate page overflows mobile viewport");await page.getByRole("button",{name:"English",exact:true}).click();await page.setViewportSize({width:1280,height:900});report.sshCertificates.webSSHAndBilingualMobile=true;
  }finally{page.off("websocket",handler);}
}
