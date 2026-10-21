import {readFileSync} from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";

const ci=readFileSync(new URL("../.github/workflows/ci.yml",import.meta.url),"utf8").replaceAll("\r\n","\n");
const release=readFileSync(new URL("../.github/workflows/release-artifacts.yml",import.meta.url),"utf8").replaceAll("\r\n","\n");
function step(text,name){
 const start=text.indexOf("      - name: "+name+"\n");
 assert.notEqual(start,-1,name);
 const end=text.indexOf("\n      - ",start+1);
 return text.slice(start,end<0?undefined:end);
}
for(const [profile,text] of [["race",ci],["native",release]]){
 test(profile+" cache is isolated by mode, toolchain, platform and dependency graph",()=>{
  const restore=step(text,"Restore "+profile+" compiler cache");
  assert.match(text, /uses: actions\/setup-go@v5\n        id: go\n/);
  assert.match(restore,/uses: actions\/cache\/restore@v4/);
  assert(restore.includes("${{ runner.os }}-${{ runner.arch }}-go-"+profile+"-${{ steps.go.outputs.go-version }}-${{ hashFiles('server/go.sum') }}"));
 });
 test(profile+" cache saves the restored primary key even after test failure",()=>{
  const save=step(text,"Save "+profile+" compiler cache");
  assert(save.includes("always() && !cancelled()"));
  assert(save.includes("steps."+profile+"-cache.outputs.cache-primary-key"));
  assert(save.includes("steps."+profile+"-cache.outputs.cache-hit != 'true'"));
  assert.match(save,/uses: actions\/cache\/save@v4/);
 });
 test(profile+" cache stores only compiler output and is optional",()=>{
  for(const name of ["Restore ","Save "]){
   const value=step(text,name+profile+" compiler cache");
   assert.match(value,/path: ~\/\.cache\/go-build\n/);
   assert.match(value,/continue-on-error: true/);
   assert.doesNotMatch(value,/JMS_DATA_DIR|qa-reports|path:.*(?:dist|data|releases)/);
  }
 });
}
test("cache failures cannot suppress backend or browser verification",()=>{
 assert.match(step(ci,"Backend tests (including PostgreSQL HA integration)"),/go test -race -timeout 20m -p 1 \.\/\.\.\./);
 for(const name of ["Backend tests (including PostgreSQL HA integration)","Backend static analysis","Backend build","Production browser end-to-end tests (includes build)","Verify clean production images and isolated ports"])
  assert.doesNotMatch(step(ci,name),/continue-on-error|if:/);
});
test("native cache does not replace six-platform archive verification or publication checks",()=>{
 const build=step(release,"Build and verify six native archives");
 for(const target of ["linux/amd64","linux/arm64","darwin/amd64","darwin/arm64","windows/amd64","windows/arm64"])assert(build.includes(target));
 assert.doesNotMatch(build,/continue-on-error|if:/);
 assert(release.indexOf("Save native compiler cache")>release.indexOf("Build and verify six native archives"));
 const publish=step(release,"Publish immutable artifacts to the existing stable release");
 assert.match(publish,/publish-release\.mjs --tag/);assert.doesNotMatch(publish,/continue-on-error|if:/);
});
test("CI jobs and native publication have explicit wall-clock limits",()=>{
 assert.match(ci,/verify:\n    runs-on: ubuntu-22\.04\n    timeout-minutes: 60/);
 assert.match(ci,/frontend:[\s\S]*?timeout-minutes: 40/);
 assert.match(ci,/docker-qa:\n    runs-on: ubuntu-latest\n    timeout-minutes: 20/);
 assert.match(release,/timeout-minutes: 45/);
});
