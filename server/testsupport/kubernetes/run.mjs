import {execFile} from 'node:child_process'
import {promisify} from 'node:util'
import {randomUUID} from 'node:crypto'
import {createServer} from 'node:http'
import {mkdtempSync, writeFileSync, rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {resolve, dirname, basename} from 'node:path'
import {isMissingDockerResource} from '../docker-qa.mjs'

const execute=promisify(execFile)
const port=Number(process.env.JMS_QA_KUBERNETES_PORT||16443)
const health=Number(process.env.JMS_QA_KUBERNETES_HEALTH_PORT||16444)
if(![port,health].every(p=>Number.isInteger(p)&&p>0&&p<65536))throw new Error('Invalid K3s ports')
const name=`jms233-kubernetes-${randomUUID()}`
const root=process.env.JMS_E2E_DATA_DIR?resolve(process.env.JMS_E2E_DATA_DIR):null
if(root&&(dirname(root).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(root).startsWith('jumpserver233-e2e-')))throw new Error('Invalid QA owner')
const owner=root?basename(root):name
const work=mkdtempSync(resolve(tmpdir(),'jms233-kubernetes-cert-'))
const record={name,owner,cert_directory:work}
if(root)writeFileSync(resolve(root,'kubernetes-container.json'),JSON.stringify(record))
if(process.env.RUNNER_TEMP&&!root)writeFileSync(resolve(process.env.RUNNER_TEMP,'jumpserver233-kubernetes-ci.json'),JSON.stringify(record))
let stopping=false,stage='image preparation'
async function cleanup(){
 try{const {stdout}=await execute('docker',['inspect','--format','{{json .Config.Labels}}',name]);if(JSON.parse(stdout)['com.jumpserver233.qa.owner']!==owner)throw new Error('Owner changed');await execute('docker',['rm','--force','--volumes',name])}catch(e){if(!isMissingDockerResource(e))throw e}
 if(dirname(resolve(work)).toLowerCase()!==resolve(tmpdir()).toLowerCase()||!basename(work).startsWith('jms233-kubernetes-cert-'))throw new Error('Invalid fixture directory')
 rmSync(work,{recursive:true,force:true})
}
async function stop(){if(stopping)return;stopping=true;try{await cleanup();process.exit(0)}catch{process.stderr.write('Owned K3s cleanup failed; retain resource record.\n');process.exit(1)}}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop())
async function docker(args){return execute('docker',args,{timeout:180000,maxBuffer:1024*1024})}
async function kubectl(args){return docker(['exec',name,'/bin/kubectl',...args])}
async function ready(args,attempts=180){for(let i=0;i<attempts;i++){try{return await kubectl(args)}catch{const state=await docker(['inspect','--format','{{.State.Running}}',name]);if(state.stdout.trim()!=='true')throw new Error('K3s stopped');await new Promise(r=>setTimeout(r,1000))}}throw new Error('K3s readiness deadline')}
try{
 const images=['rancher/k3s:v1.37.1-k3s1','busybox:1.37.0','rancher/mirrored-pause:3.6']
 for(const image of images){try{await docker(['image','inspect',image])}catch{await docker(['pull',image])}}
 process.stdout.write('Starting owned K3s TLS fixture…\n');stage='API startup'
 const args=['run','--detach','--privileged','--name',name,'--label',`com.jumpserver233.qa.owner=${owner}`,'--publish',`127.0.0.1:${port}:6443`,'--tmpfs','/run','--tmpfs','/var/run']
 const network=process.env.JMS_QA_KUBERNETES_NETWORK;if(network){if(!/^[A-Za-z0-9_.-]+$/.test(network))throw new Error('Invalid network');args.push('--network',network)}
 args.push(images[0],'server','--disable','traefik,servicelb,metrics-server,local-storage','--disable-cloud-controller','--disable-network-policy','--flannel-backend=none','--node-name','qa-node','--pause-image',images[2],'--tls-san','kubernetes.synthetic.invalid')
 await docker(args)
 await ready(['get','--raw=/readyz'])
 stage='container runtime image import'
 const archive=resolve(work,'images.tar');await docker(['save','--output',archive,images[1],images[2]]);await docker(['cp',archive,`${name}:/tmp/qa-images.tar`]);await docker(['exec',name,'/bin/ctr','images','import','/tmp/qa-images.tar'])
 stage='namespace and Pod setup'
 const pod=(namespace)=>({apiVersion:'v1',kind:'Pod',metadata:{name:'qa-shell',namespace},spec:{serviceAccountName:'qadb',nodeName:"qa-node",tolerations:[{key:"node.kubernetes.io/not-ready",operator:"Exists",effect:"NoExecute"},{key:"node.kubernetes.io/unreachable",operator:"Exists",effect:"NoExecute"}],hostNetwork:true,dnsPolicy:'Default',automountServiceAccountToken:false,terminationGracePeriodSeconds:0,containers:['main','sidecar'].map(n=>({name:n,image:images[1],imagePullPolicy:'Never',command:['/bin/sh','-c','sleep 1000000'],securityContext:{runAsUser:1000,allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}},resources:{requests:{cpu:'10m',memory:'8Mi'},limits:{cpu:'250m',memory:'64Mi'}}}))}})
 const objects=[{apiVersion:'v1',kind:'Namespace',metadata:{name:'jms-qa'}},{apiVersion:'v1',kind:'Namespace',metadata:{name:'jms-forbidden'}},{apiVersion:'v1',kind:'ServiceAccount',metadata:{name:'qadb',namespace:'jms-qa'}},{apiVersion:'rbac.authorization.k8s.io/v1',kind:'Role',metadata:{name:'qa-exec',namespace:'jms-qa'},rules:[{apiGroups:[''],resources:['pods'],verbs:['get','list']},{apiGroups:[''],resources:['pods/exec'],verbs:['get','create']}]},{apiVersion:'rbac.authorization.k8s.io/v1',kind:'RoleBinding',metadata:{name:'qa-exec',namespace:'jms-qa'},subjects:[{kind:'ServiceAccount',name:'qadb',namespace:'jms-qa'}],roleRef:{apiGroup:'rbac.authorization.k8s.io',kind:'Role',name:'qa-exec'}},{apiVersion:'v1',kind:'ServiceAccount',metadata:{name:'qadb',namespace:'jms-forbidden'}},pod('jms-qa'),pod('jms-forbidden')]
 const manifest=resolve(work,'resources.json');writeFileSync(manifest,JSON.stringify({apiVersion:'v1',kind:'List',items:objects}));await docker(['cp',manifest,`${name}:/tmp/qa-resources.json`]);await kubectl(['apply','-f','/tmp/qa-resources.json']);await ready(['wait','--for=condition=Ready','pod/qa-shell','-n','jms-qa','--timeout=2s'])
 stage='scoped identity preparation'
 const {stdout:token}=await kubectl(['create','token','qadb','-n','jms-qa','--duration=24h'])
 const {stdout:ca}=await kubectl(['config','view','--raw','-o','jsonpath={.clusters[0].cluster.certificate-authority-data}'])
 const metadata={ready:true,address:`127.0.0.1:${port}`,network_address:`${name}:6443`,container_name:name,owner,root_ca_pem:Buffer.from(ca,'base64').toString('utf8'),server_name:'kubernetes.synthetic.invalid',namespace:'jms-qa',pod:'qa-shell',containers:['main','sidecar'],token:token.trim()}
 const server=createServer((req,res)=>{if(req.method!=='GET'||req.url!=='/health'){res.writeHead(404).end();return}res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(metadata))})
 server.on('error',()=>void stop());server.listen(health,'127.0.0.1',()=>process.stdout.write(`K3s QA ready on 127.0.0.1:${port}; health ${health}\n`))
}catch(e){process.stderr.write(`K3s fixture failed during ${stage}; credentials are omitted.\n`);if(stage!=='scoped identity preparation')process.stderr.write(String(e.stderr||e.code||'startup failure').slice(-1600)+'\n');try{await cleanup()}catch{process.stderr.write('Owned K3s resource record retained for cleanup.\n')}process.exitCode=1}
