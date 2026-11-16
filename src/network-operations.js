(function(root){
"use strict";
const data=Object.freeze({
 label:"SYNTHETIC NETWORK TELEMETRY · NOT IBEDC LIVE DATA",
 generatedAt:"2026-10-31T23:59:00Z",
 feeders:[
  {id:"IB-NORTH-04",area:"Ibadan North",availability:94.2,peakLoad:87,voltageDeviation:4.8,attention:"Operator review",period:"2026-10-01 to 2026-10-31",evidence:["Synthetic SCADA-like interval fixture: 15-minute aggregates","Peak load above illustrative 85% review threshold","Voltage deviation exceeds illustrative 4% review threshold"],recommendation:"Validate source telemetry quality, feeder boundary and recent maintenance history. Escalate findings to the authorised network operations engineer; do not issue switching instructions from this PoV."},
  {id:"IB-SOUTH-02",area:"Ibadan South",availability:98.1,peakLoad:72,voltageDeviation:1.2,attention:"Normal",period:"2026-10-01 to 2026-10-31",evidence:["Synthetic interval fixture","No configured demonstration threshold exceeded"],recommendation:"Continue routine monitoring and compare with verified operational records."},
  {id:"AKY-01",area:"Akinyele",availability:96.7,peakLoad:79,voltageDeviation:2.6,attention:"Monitor",period:"2026-10-01 to 2026-10-31",evidence:["Synthetic interval fixture","Load trend approaching illustrative monitoring threshold"],recommendation:"Review load trend against validated historical data and planned demand before prioritising field inspection."},
  {id:"OGB-03",area:"Ogbomosho",availability:95.4,peakLoad:83,voltageDeviation:3.1,attention:"Monitor",period:"2026-10-01 to 2026-10-31",evidence:["Synthetic interval fixture","Availability below illustrative 96% monitoring threshold"],recommendation:"Check outage records, data completeness and planned maintenance context with the responsible operations team."},
  {id:"IB-EAST-06",area:"Ibadan East",availability:97.5,peakLoad:68,voltageDeviation:1.7,attention:"Normal",period:"2026-10-01 to 2026-10-31",evidence:["Synthetic interval fixture","No configured demonstration threshold exceeded"],recommendation:"Continue routine monitoring."}
 ],
 transformers:[
  {id:"TX-IBN-220",area:"Ibadan North",load:91,conditionIndex:78,review:"Review",evidence:["Synthetic condition index: 78/100","Illustrative load review threshold: 90%","No actual oil, thermal or dissolved-gas test results are represented"],recommendation:"Verify asset identity and inspect the latest approved condition-monitoring and maintenance records."},
  {id:"TX-IBS-114",area:"Ibadan South",load:67,conditionIndex:24,review:"Normal",evidence:["Synthetic condition index: 24/100","Illustrative load below review threshold"],recommendation:"Continue scheduled condition monitoring."},
  {id:"TX-AKY-031",area:"Akinyele",load:84,conditionIndex:52,review:"Monitor",evidence:["Synthetic condition index: 52/100","Illustrative watch band: 50–69"],recommendation:"Compare with verified inspection history and loading profile; prioritise review if the trend persists."},
  {id:"TX-OGB-052",area:"Ogbomosho",load:76,conditionIndex:33,review:"Normal",evidence:["Synthetic condition index: 33/100"],recommendation:"Continue routine monitoring."}
 ]
});
function snapshot(){return JSON.parse(JSON.stringify(data))}
function summary(d=snapshot()){
 const loads=d.feeders.map(x=>x.peakLoad);
 const total=d.feeders.length;
 return {
  feederCount:total,
  averageAvailability:Number((d.feeders.reduce((s,x)=>s+x.availability,0)/total).toFixed(1)),
  feedersForReview:d.feeders.filter(x=>x.attention==="Operator review").length,
  feedersToMonitor:d.feeders.filter(x=>x.attention==="Monitor").length,
  peakLoad:Math.max(...loads),
  transformerReviews:d.transformers.filter(x=>x.review==="Review").length
 };
}
function node(tag,cls,text){const n=root.document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text);return n}
function detail(item,type){
 const host=root.document.getElementById("network-detail");if(!host)return;
 host.replaceChildren();
 const title=node("h3","",item.id);title.style.marginTop="0";
 host.append(title,node("p","muted",type+" · "+item.area));
 const fields=type==="Feeder"?[
  ["Availability",item.availability+"%"],["Peak loading",item.peakLoad+"%"],["Voltage deviation",item.voltageDeviation+"%"],["Attention",item.attention],["Data period",item.period]
 ]:[["Loading",item.load+"%"],["Condition index",item.conditionIndex+"/100"],["Review state",item.review]];
 fields.forEach(([k,v])=>{const f=node("div","field");f.style.marginBottom="7px";f.append(node("label","",k),node("strong","",v));host.append(f)});
 host.append(node("strong","","Synthetic evidence"));
 const ul=node("ul");item.evidence.forEach(e=>ul.append(node("li","",e)));host.append(ul);
 host.append(node("strong","","Recommended human follow-up"),node("p","",item.recommendation));
}
function renderTable(){
 if(!root.document)return;
 const body=root.document.getElementById("network-feeders");if(!body)return;
 const q=(root.document.getElementById("network-search")?.value||"").toLowerCase();
 const status=root.document.getElementById("network-status")?.value||"";
 body.replaceChildren();
 const rows=snapshot().feeders.filter(f=>(!q||(f.id+" "+f.area).toLowerCase().includes(q))&&(!status||f.attention===status));
 rows.forEach(f=>{const tr=node("tr");[f.id,f.area,f.availability+"%",f.peakLoad+"%",f.voltageDeviation+"%"].forEach(v=>tr.append(node("td","",v)));const td=node("td");td.append(node("span","tag "+(f.attention==="Operator review"?"high":f.attention==="Monitor"?"medium":"low"),f.attention));tr.append(td);const action=node("td");const b=node("button","linkbtn","Inspect →");b.type="button";b.addEventListener("click",()=>detail(f,"Feeder"));action.append(b);tr.append(action);body.append(tr)});
 if(!rows.length)body.append(node("tr","", "No feeders match these filters."));
}
function render(){
 if(!root.document)return;
 const d=snapshot(),s=summary(d);
 const kpis=root.document.getElementById("network-kpis");if(!kpis)return;
 kpis.replaceChildren();
 [["Feeder records",s.feederCount,"Synthetic feeder fixtures"],["Average availability",s.averageAvailability+"%","Unweighted demo average"],["Operator review",s.feedersForReview,"Feeder signals requiring review"],["Transformer reviews",s.transformerReviews,"Synthetic asset condition flags"]].forEach(([label,value,note])=>{const card=node("div","card");card.append(node("div","klabel",label),node("div","kvalue",value),node("div","kmeta",note));kpis.append(card)});
 const profile=root.document.getElementById("network-load-profile");profile.replaceChildren();d.feeders.forEach(f=>{const row=node("div","barrow");row.append(node("span","",f.id));const bar=node("div","bar"),fill=node("i");fill.style.width=f.peakLoad+"%";bar.append(fill);row.append(bar,node("strong","",f.peakLoad+"%"));profile.append(row)});
 const alerts=root.document.getElementById("network-alerts");alerts.replaceChildren();
 [...d.feeders.filter(f=>f.attention!=="Normal").map(f=>({severity:f.attention==="Operator review"?"High":"Medium",title:"Feeder "+f.id,description:f.area+" · "+f.peakLoad+"% peak load · "+f.availability+"% availability",item:f,type:"Feeder"})),...d.transformers.filter(t=>t.review!=="Normal").map(t=>({severity:t.review==="Review"?"High":"Medium",title:"Transformer "+t.id,description:t.area+" · "+t.load+"% loading · condition index "+t.conditionIndex+"/100",item:t,type:"Transformer"}))].forEach(a=>{const card=node("div","field");card.style.marginBottom="8px";card.append(node("span","tag "+(a.severity==="High"?"high":"medium"),a.severity),node("strong","",a.title),node("p","muted",a.description));const b=node("button","linkbtn","Inspect evidence →");b.type="button";b.addEventListener("click",()=>detail(a.item,a.type));card.append(b);alerts.append(card)});
 const tbody=root.document.getElementById("network-transformers");tbody.replaceChildren();d.transformers.forEach(t=>{const tr=node("tr");[t.id,t.area,t.load+"%",t.conditionIndex+"/100"].forEach(v=>tr.append(node("td","",v)));const td=node("td");td.append(node("span","tag "+(t.review==="Review"?"high":t.review==="Monitor"?"medium":"low"),t.review));tr.append(td);tbody.append(tr)});
 renderTable();
}
const api={snapshot,summary,render,renderTable};
if(typeof module!=="undefined"&&module.exports)module.exports=api;
root.PowerOpsNetwork=api;
})(typeof window!=="undefined"?window:globalThis);
