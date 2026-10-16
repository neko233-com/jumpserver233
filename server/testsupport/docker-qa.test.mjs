import {test} from 'node:test';
import assert from 'node:assert/strict';
import {isMissingDockerResource,buildQAImage} from './docker-qa.mjs';
test('missing Docker resource errors are case independent and fail closed',()=>{
 for(const stderr of ['error: no such object: qa','Error: No such container: qa'])assert.equal(isMissingDockerResource({stderr}),true);
 for(const stderr of ['EOF','permission denied','Docker daemon unavailable'])assert.equal(isMissingDockerResource({stderr}),false);
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
