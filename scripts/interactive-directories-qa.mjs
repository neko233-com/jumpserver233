// Authored for the final unified native run. Reuses its existing SSH container,
// API, controller and temporary data; this module never creates another stack.
import {randomUUID} from "node:crypto";
import {setTimeout as delay} from "node:timers/promises";

async function waitFor(check,label,timeout=15000){const until=Date.now()+timeout;while(Date.now()<until){if(await check())return;await delay(25);}throw Error("Interactive directory QA timed out: "+label);}
async function attach(url,created){
 const address=new URL(created.websocket_url,url);address.protocol=address.protocol==="https:"?"wss:":"ws:";
 const socket=new WebSocket(address,["jms233-terminal-v1","jms233-ticket."+created.ticket]);socket.binaryType="arraybuffer";
 const state={socket,text:"",notices:[],closed:false};
 socket.addEventListener("message",event=>{if(typeof event.data==="string"){try{state.notices.push(JSON.parse(event.data));if(state.notices.length>100)state.notices.shift();}catch{}}else{state.text+=Buffer.from(event.data).toString("utf8");if(state.text.length>131072)state.text=state.text.slice(-65536);}});
 socket.addEventListener("close",()=>{state.closed=true;});socket.addEventListener("error",()=>{});
 await waitFor(()=>socket.readyState===WebSocket.OPEN,"WebSocket attachment");
 await waitFor(()=>/(?:^|\r?\n)[^\r\n]*[$#] $/.test(state.text),"initial shell prompt");
 return state;
}
async function line(t,command,notice){
 const before=t.text.length,index=t.notices.length;
 t.socket.send(Buffer.from(command+"\r"));
 if(notice)await waitFor(()=>t.notices.slice(index).some(n=>n.type===notice),notice);
 if(notice!=="command_review_pending")await waitFor(()=>/\n[^\r\n]*[$#] $/.test(t.text.slice(before)),"shell prompt after input");
 return t.notices.slice(index);
}

export async function verifyInteractiveDirectories({api,admin,operator,asset,workspace,url,run,sshHost,report}){
 const directory=workspace+"/pty-"+randomUUID();
 if(!directory.startsWith("/home/keyqa/workspace/pty-")||directory.includes(".."))throw Error("Unexpected owned interactive QA directory");
 const rules=[],sessions=[],terminals=[];
 const ensure=async name=>{await run("docker",["exec",sshHost,"mkdir","-p",name]);await run("docker",["exec",sshHost,"chown","-R","keyqa:keyqa",name]);};
 const open=async()=>{
  const input={asset_id:asset.id,cols:100,rows:30};
  const pending=await api("POST","/api/v1/sessions",input,operator,202);
  await api("POST",`/api/v1/access-reviews/${pending.review_id}/approve`,undefined,admin,204);
  const created=await api("POST","/api/v1/sessions",input,operator,201);sessions.push(created.session_id);
  const terminal=await attach(url,created);terminals.push(terminal);return {created,terminal};
 };
 const addRule=async(name,command,action,mode,path)=>{const r=await api("POST","/api/v1/command-filters",{name,asset_id:asset.id,account:asset.username,match:"exact",pattern:command,action,priority:90,directory_match:mode,directory_pattern:path},admin,201);rules.push(r.id);return r;};
 try{
  for(const suffix of ["/deploy/releases/12","/sibling"])await ensure(directory+suffix);
  await addRule("PTY exact directory","mkdir pty-exact","deny","exact",directory+"/deploy");
  await addRule("PTY directory subtree","mkdir pty-tree","deny","tree",directory+"/deploy");
  await addRule("PTY directory regex","mkdir pty-regex","deny","regex",directory+"/deploy/releases/[0-9]+");
  await addRule("PTY directory review","pwd","review","exact",directory+"/deploy");
  const {created,terminal}=await open();
  await line(terminal,"cd "+directory+"/deploy");
  const blocked=await line(terminal,"mkdir pty-exact","command_blocked");
  if(blocked.some(n=>n.type==="command_blocked"&&n.directory_required))throw Error("Native terminal did not supply actual cwd proof");
  await line(terminal,"cd releases/12");
  await line(terminal,"mkdir pty-tree","command_blocked");
  await line(terminal,"mkdir pty-regex","command_blocked");
  for(const name of ["/deploy/pty-exact","/deploy/releases/12/pty-tree","/deploy/releases/12/pty-regex"])await run("docker",["exec",sshHost,"test","!","-e",directory+name]);
  await line(terminal,"cd "+directory+"/sibling");
  await line(terminal,"mkdir pty-exact");await run("docker",["exec",sshHost,"test","-d",directory+"/sibling/pty-exact"]);
  await line(terminal,"cd "+directory+"/deploy");
  const pending=await line(terminal,"pwd","command_review_pending");
  const review=pending.find(n=>n.type==="command_review_pending");
  const before=terminal.text.length;
  await api("POST",`/api/v1/command-reviews/${review.review_id}/approve`,undefined,admin,204);
  await waitFor(()=>terminal.text.slice(before).includes(directory+"/deploy")&&/\n[^\r\n]*[$#] $/.test(terminal.text.slice(before)),"approved pwd output");
  await api("POST",`/api/v1/command-reviews/${review.review_id}/approve`,undefined,admin,404);
  const changed=await line(terminal,"pwd","command_review_pending");
  const changedReview=changed.find(n=>n.type==="command_review_pending");
  await run("docker",["exec",sshHost,"mv",directory+"/deploy",directory+"/previous"]);await ensure(directory+"/deploy");
  const index=terminal.notices.length;
  await api("POST",`/api/v1/command-reviews/${changedReview.review_id}/approve`,undefined,admin,204);
  await waitFor(()=>terminal.notices.slice(index).some(n=>n.type==="command_review_denied"),"replacement directory rejection");
  const audit=await api("GET",`/api/v1/sessions/${created.session_id}/commands?offset=0&limit=100`,undefined,admin);
  if(!audit.results.some(v=>v.command==="mkdir pty-exact"&&v.outcome==="blocked"&&v.directory_verified&&v.working_directory===directory+"/deploy"))throw Error("Terminal audit lost trusted directory");
  if(!audit.results.some(v=>v.command==="pwd"&&v.outcome==="approved")||!audit.results.some(v=>v.command==="pwd"&&v.outcome==="denied"))throw Error("Terminal review outcomes were not preserved");
  report.interactiveDirectories={actualKernelCWD:true,exactTreeRegex:true,differentDirectoryAllowed:true,approvedCommand:true,directoryReplacementRefused:true,approvalReplayRefused:true,encryptedAuditDirectory:true};
 }finally{
  for(const t of terminals){try{t.socket.close();}catch{}}
  for(let round=0;round<2;round++){
   for(const id of sessions)await api("DELETE","/api/v1/sessions/"+id,undefined,admin,204);
   const current=await api("GET","/api/v1/command-filters",undefined,admin);
   for(const id of rules)if(current.some(r=>r.id===id))await api("DELETE","/api/v1/command-filters/"+id,undefined,admin,204);
   await run("docker",["exec",sshHost,"sh","-ceu",'case "$1" in /home/keyqa/workspace/pty-*) ;; *) exit 1;; esac; rm -rf -- "$1"',"sh",directory]);
  }
  await waitFor(()=>terminals.every(t=>t.closed),"owned WebSocket cleanup",3000);
 }
}
