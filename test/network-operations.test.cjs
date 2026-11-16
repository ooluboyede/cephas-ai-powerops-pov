const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const network=require('../src/network-operations.js');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');

test('network operations is a first-class workspace in the overall PowerOps PoV',()=>{
 assert.match(html,/data-page="network"/);
 assert.match(html,/id="page-network"/);
 assert.match(html,/Network Operations Intelligence/);
 assert.match(html,/window\.PowerOpsNetwork\.render\(\)/);
});
test('synthetic network snapshot contains feeder and transformer intelligence',()=>{
 const d=network.snapshot();
 assert.equal(d.feeders.length,5);
 assert.equal(d.transformers.length,4);
 assert.ok(d.feeders.every(x=>x.id&&x.area&&x.availability>=0&&x.availability<=100&&x.peakLoad>=0&&x.peakLoad<=100));
 assert.ok(d.transformers.every(x=>x.id&&x.conditionIndex>=0&&x.conditionIndex<=100));
});
test('network KPIs are derived deterministically from fixtures',()=>{
 const s=network.summary();
 assert.equal(s.feederCount,5);
 assert.equal(s.averageAvailability,96.4);
 assert.equal(s.feedersForReview,1);
 assert.equal(s.feedersToMonitor,2);
 assert.equal(s.peakLoad,87);
 assert.equal(s.transformerReviews,1);
 assert.deepEqual(s,network.summary());
});
test('all operational recommendations are human review only',()=>{
 const d=network.snapshot();
 const recommendations=[...d.feeders,...d.transformers].map(x=>x.recommendation).join(' ').toLowerCase();
 assert.match(recommendations,/review|monitor|inspect|validate|continue/);
 assert.match(html,/not connected to SCADA, ADMS or DMS/);
 assert.match(html,/cannot operate breakers, change taps, switch feeders, dispatch crews or issue control commands/);
 assert.match(d.label,/SYNTHETIC/);
});
test('network module does not connect to revenue assurance state or external systems',()=>{
 const source=fs.readFileSync(path.join(__dirname,'..','src','network-operations.js'),'utf8');
 assert.doesNotMatch(source,/fetch\s*\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage/);
 assert.doesNotMatch(source,/PowerOpsReconciliation|findings\s*=|Revenue Assurance/i);
});
