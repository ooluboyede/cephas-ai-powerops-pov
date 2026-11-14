const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const network=require('../src/network-operations.js');
const features=require('../src/feature-engineering.js');
const ml=require('../src/ml-intelligence.js');
const triage=require('../src/alert-triage.js');
const integration=require('../src/network-alert-intelligence.js');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');

test('PowerOps Network Alert Intelligence is wired into the overall Network Operations workspace',()=>{
 assert.match(html,/id="network-ml-kpis"/);
 assert.match(html,/id="network-ml-alerts"/);
 assert.match(html,/id="network-ml-evaluation"/);
 assert.match(html,/src\/feature-engineering\.js/);
 assert.match(html,/src\/ml-intelligence\.js/);
 assert.match(html,/src\/network-alert-intelligence\.js/);
 assert.equal(typeof integration.render,'function');
});
test('feature engineering emits deterministic, versioned model-ready features',()=>{
 const rows=features.build(network.snapshot().feeders);
 assert.equal(rows.length,5);
 assert.ok(rows.every(x=>x.feature_version===features.VERSION&&x.sample_count===8));
 assert.deepEqual(rows,features.build(network.snapshot().feeders));
 assert.ok(rows.every(x=>Number.isFinite(x.mean_load_pct)&&Number.isFinite(x.voltage_load_interaction)));
});
test('ML inference is deterministic, explainable and scoped to novelty scoring',()=>{
 const rows=features.build(network.snapshot().feeders),a=ml.infer(rows),b=ml.infer(rows);
 assert.deepEqual(a,b);
 assert.ok(a.every(x=>x.model_version===ml.VERSION&&x.explanations.length===3&&x.anomaly_score>=0&&x.anomaly_score<=100));
 assert.match(a[0].confidence_label,/not a calibrated probability/);
 const extreme=ml.score({entity_id:'SYN-EXTREME',feature_version:features.VERSION,availability_pct:90,mean_load_pct:98,load_stddev_pct:8,mean_voltage_deviation_pct:8,voltage_load_interaction:7.84,high_load_interval_ratio:1});
 assert.equal(extreme.band,'High');
});
test('synthetic benchmark reports metrics with an explicit non-field limitation',()=>{
 const result=ml.evaluate();
 assert.equal(result.benchmark_cases,4);
 assert.match(result.scope,/not a field-performance estimate/);
 assert.ok(result.precision>=0&&result.precision<=1&&result.recall>=0&&result.recall<=1);
});
test('triage supports assignment, acknowledgement, escalation and mandatory closure reason',()=>{
 triage.seed(ml.infer(features.build(network.snapshot().feeders)));
 const id=network.snapshot().feeders[0].id;
 assert.throws(()=>triage.update(id,'close',''),/mandatory/);
 assert.equal(triage.update(id,'assign','Network Control Room').assigned_to,'Network Control Room');
 assert.equal(triage.update(id,'acknowledge').status,'Acknowledged');
 assert.equal(triage.update(id,'escalate','Engineer review').status,'Escalation recommended');
 assert.equal(triage.update(id,'close','Reviewed against approved synthetic evidence').status,'Closed');
 assert.equal(triage.list().find(x=>x.entity_id===id).history.length,5);
});
test('ML modules are synthetic-only and do not call external services or control systems',()=>{
 for(const file of ['feature-engineering.js','ml-intelligence.js','alert-triage.js','network-alert-intelligence.js']){
  const source=fs.readFileSync(path.join(__dirname,'..','src',file),'utf8');
  assert.doesNotMatch(source,/fetch\s*\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage|SCADA|ADMS|DMS/);
 }
});
