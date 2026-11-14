const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {getSnapshot}=require('../src/powerops-command-centre.js');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');

test('PowerOps is the product landing page and not Revenue Assurance',()=>{
 assert.match(html,/<title>CEPHAS PowerOps \| Revenue Assurance PoV<\/title>/);
 assert.match(html,/id="page-powerops"/);
 assert.match(html,/data-page="powerops"/);
 assert.match(html,/UTILITY OPERATIONS INTELLIGENCE/);
});
test('command centre exposes broad utility modules with honest planned status',()=>{
 const data=getSnapshot();
 const names=data.modules.map(x=>x.name);
 for(const name of ['Network operations','Outage & fault intelligence','Asset health & maintenance','Metering & energy intelligence','Customer operations','Field workforce','Revenue Assurance','Forecasting & planning']) assert.ok(names.includes(name),name);
 assert.equal(data.modules.find(x=>x.name==='Revenue Assurance').status,'Initial module slice');
 assert.ok(data.modules.filter(x=>x.name!=='Revenue Assurance').every(x=>x.status==='Planned'));
});
test('all command-centre records are clearly synthetic and advisory-only',()=>{
 const data=getSnapshot();
 assert.match(data.label,/SYNTHETIC/);
 assert.match(html,/Advisory-only demonstration/);
 assert.match(html,/does not issue switching, dispatch, SCADA, ADMS, DMS, meter or disconnection commands/);
});
test('module identifiers and feeder identifiers are unique',()=>{
 const data=getSnapshot();
 assert.equal(new Set(data.modules.map(x=>x.id)).size,data.modules.length);
 assert.equal(new Set(data.feeders.map(x=>x.id)).size,data.feeders.length);
});
