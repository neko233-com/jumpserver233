// Read-only loopback preview of ANSI frames exported by native Go tests.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('..',import.meta.url));
const args=process.argv.slice(2);
if(args.includes('--help')){console.log('node scripts/native-workbench-preview.mjs [--port 15223] [--reports .cache/qa-reports/native-workbench-20261022/frames]');process.exit(0);}
function option(name,fallback){const i=args.indexOf(name);if(i<0)return fallback;if(!args[i+1]||args[i+1].startsWith('--'))throw Error('Missing '+name);const value=args[i+1];args.splice(i,2);return value;}
const port=Number(option('--port','15223'));
const reports=resolve(root,option('--reports','.cache/qa-reports/native-workbench-20261022/frames'));
if(args.length||!Number.isInteger(port)||port<1025||port>65535)throw Error('Use --help');
const cases=new Map([['wide',{file:'workbench-wide.ansi',cols:110}],['narrow',{file:'workbench-narrow.ansi',cols:56}],['english',{file:'workbench-english.ansi',cols:110}]]);
const html=`<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/xterm.css"><style>html,body{margin:0;background:#0f111c;color:#e8edf7;font:14px system-ui}main{margin:28px auto;width:max-content;max-width:100%}header{padding:0 0 16px;color:#b4c1d7;font-size:12px}#terminal{width:1160px;max-width:100vw}.xterm-viewport{scrollbar-width:none}</style></head><body><main><header>JumpServer233 · native Go frame</header><div id="terminal"></div></main><script src="/xterm.js"></script><script>(async()=>{const kind=new URL(location.href).searchParams.get('case')||'wide';const narrow=kind==='narrow';document.querySelector('#terminal').style.width=narrow?'600px':'1160px';const term=new Terminal({cols:narrow?56:110,rows:28,fontFamily:'Cascadia Mono,Consolas,monospace',fontSize:16,lineHeight:1.2,cursorBlink:false,theme:{background:'#0f111c',foreground:'#e8edf7'},allowProposedApi:false});term.open(document.querySelector('#terminal'));const res=await fetch('/frame?case='+encodeURIComponent(kind));if(!res.ok)throw Error('Frame unavailable');term.write(await res.text(),()=>{document.documentElement.dataset.rendered='true'});})();</script></body></html>`;
const server=createServer((req,res)=>{try{const u=new URL(req.url,'http://127.0.0.1');let body,type;if(u.pathname==='/'){body=html;type='text/html; charset=utf-8';}else if(u.pathname==='/frame'){const c=cases.get(u.searchParams.get('case'));if(!c){res.writeHead(404);res.end();return;}body=readFileSync(resolve(reports,c.file));type='text/plain; charset=utf-8';}else if(u.pathname==='/xterm.js'||u.pathname==='/xterm.css'){body=readFileSync(resolve(root,'web/node_modules/@xterm/xterm',u.pathname.endsWith('.js')?'lib/xterm.js':'css/xterm.css'));type=u.pathname.endsWith('.js')?'text/javascript':'text/css';}else{res.writeHead(404);res.end();return;}res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(body);}catch{res.writeHead(500);res.end('Preview unavailable');}});
server.listen(port,'127.0.0.1',()=>console.log('Native frame preview: http://127.0.0.1:'+port));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>process.exit(0)));
