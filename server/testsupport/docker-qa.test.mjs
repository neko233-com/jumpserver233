import {test} from 'node:test';
import assert from 'node:assert/strict';
import {isMissingDockerResource,buildQAImage} from './docker-qa.mjs';
test('missing Docker resource errors are case independent and fail closed',()=>{
 for(const stderr of ['error: no such object: qa','Error: No such container: qa','Error: No such container: jms233-unauthorized','Error: No such container: jms233-eof','Error response from daemon: network jms233-qa-123 not found\n'])assert.equal(isMissingDockerResource({stderr}),true);
 for(const stderr of ['EOF','permission denied','Docker daemon unavailable','No such object: permission denied','Error response from daemon: network qa not found: permission denied'])assert.equal(isMissingDockerResource({stderr}),false);
});
test('QA image build retries a transient read failure and returns the original success',async()=>{
 let calls=0;const success={stdout:'built'};assert.equal(await buildQAImage(async()=>{if(++calls===1)throw Object.assign(new Error('registry'),{stderr:'Head https://registry.invalid: EOF'});return success;},['build']),success);assert.equal(calls,2);
});
test('QA image build does not retry deterministic failures',async()=>{
 let calls=0;await assert.rejects(buildQAImage(async()=>{calls++;throw new Error('Dockerfile missing');},['build']),/Dockerfile missing/);assert.equal(calls,1);
});
test('QA image build stops after three transient failures',async()=>{
 let calls=0;await assert.rejects(buildQAImage(async()=>{calls++;throw new Error('EOF');},['build']),/EOF/);assert.equal(calls,3);
});
test('QA image preparation retries only a Windows Docker context metadata sharing violation',async()=>{
 let calls=0;const success={stdout:'built'};
 const detail='Failed to initialize: unable to resolve docker endpoint: context "desktop-linux": open C:/synthetic/.docker/contexts/meta/id/meta.json: The process cannot access the file because it is being used by another process.';
 assert.equal(await buildQAImage(async()=>{if(++calls===1)throw Object.assign(new Error('context'),{stderr:detail});return success},['build']),success);assert.equal(calls,2);
 for(const message of ['open Dockerfile: The process cannot access the file because it is being used by another process.','unable to resolve docker endpoint: context "desktop-linux": open C:/meta.json: Access is denied.']){
  calls=0;await assert.rejects(buildQAImage(async()=>{calls++;throw new Error(message)},['build']));assert.equal(calls,1);
 }
});
