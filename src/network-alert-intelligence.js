(function(root){
"use strict";
function el(tag,cls,txt){const n=document.createElement(tag);if(cls)n.className=cls;if(txt!==undefined)n.textContent=String(txt);return n}
function render(){
 if(!root.document||!root.PowerOpsNetwork||!root.PowerOpsFeatures||!root.PowerOpsML||!root.PowerOpsTriage)return;
 const feeders=root.PowerOpsNetwork.snapshot().feeders;
 const features=root.PowerOpsFeatures.build(feeders);
 const results=root.PowerOpsML.infer(features);
 root.PowerOpsTriage.seed(results);
 const kpis=document.getElementById("network-ml-kpis");
 const alerts=document.getElementById("network-ml-alerts");
 const evaluation=document.getElementById("network-ml-evaluation");
 if(!kpis||!alerts||!evaluation)return;
 const high=results.filter(x=>x.band==="High").length,elevated=results.filter(x=>x.band==="Elevated").length;
 kpis.replaceChildren();
 [["Model",root.PowerOpsML.VERSION,"Exploratory k-nearest-neighbour novelty model"],["Features",root.PowerOpsML.KEYS.length,"Versioned engineered signals"],["Elevated / high",elevated+" / "+high,"Prioritisation bands, not probabilities"],["Training references",root.PowerOpsML.baselineSize,"Synthetic baseline profiles"]].forEach(([a,b,c])=>{const card=el("div","card");card.append(el("div","klabel",a),el("div","kvalue",b),el("div","kmeta",c));kpis.append(card)});
 alerts.replaceChildren();
 results.sort((a,b)=>b.anomaly_score-a.anomaly_score).forEach(a=>{
  const card=el("div","field");card.style.marginBottom="10px";
  card.append(el("div","tag "+(a.band==="High"?"high":a.band==="Elevated"?"medium":"low"),a.band+" · score "+a.anomaly_score+"/100"),el("strong","",a.entity_id));
  card.append(el("p","muted","Novelty score is a relative distance from synthetic baseline profiles; it is not a fault probability."));
  const why=el("ul");a.explanations.forEach(x=>why.append(el("li","",x.feature.replaceAll("_"," ")+": "+x.direction+" baseline by "+x.deviation+" (scaled contribution "+x.weight+")")));card.append(why);
  const state=root.PowerOpsTriage.list().find(x=>x.entity_id===a.entity_id);
  const status=el("p","");status.append(el("strong","","Triage: "),document.createTextNode(state.status+" · Assigned: "+state.assigned_to));card.append(status);
  const assignee=el("input","");assignee.placeholder="Assign to operator / team";assignee.setAttribute("aria-label","Assignee for "+a.entity_id);assignee.style.maxWidth="220px";assignee.style.padding="7px";assignee.style.border="1px solid #dce3ec";assignee.style.borderRadius="6px";
  const reason=el("input","");reason.placeholder="Required closure reason";reason.setAttribute("aria-label","Closure reason for "+a.entity_id);reason.style.maxWidth="220px";reason.style.padding="7px";reason.style.border="1px solid #dce3ec";reason.style.borderRadius="6px";
  const actions=el("div","split");
  const assign=el("button","btn","Assign");assign.type="button";assign.addEventListener("click",()=>{try{root.PowerOpsTriage.update(a.entity_id,"assign",assignee.value);render()}catch(e){alert(e.message)}});
  const ack=el("button","btn","Acknowledge");ack.type="button";ack.addEventListener("click",()=>{root.PowerOpsTriage.update(a.entity_id,"acknowledge");render()});
  const escalate=el("button","btn","Recommend escalation");escalate.type="button";escalate.addEventListener("click",()=>{root.PowerOpsTriage.update(a.entity_id,"escalate","Human escalation requested");render()});
  const close=el("button","btn","Close with reason");close.type="button";close.addEventListener("click",()=>{try{root.PowerOpsTriage.update(a.entity_id,"close",reason.value);render()}catch(e){alert(e.message)}});
  actions.append(assign,ack,escalate,close);card.append(assignee,reason,actions);alerts.append(card);
 });
 const ev=root.PowerOpsML.evaluate();
 evaluation.replaceChildren();
 [["Benchmark cases",ev.benchmark_cases],["Precision",ev.precision],["Recall",ev.recall],["False positives",ev.false_positive+" · false negatives "+ev.false_negative]].forEach(([a,b])=>{const cell=el("div","field");cell.append(el("div","klabel",a),el("strong","",b));evaluation.append(cell)});
 const note=el("p","muted",ev.scope+" · This benchmark is deliberately small and synthetic; it is not evidence of IBEDC or field accuracy.");evaluation.append(note);
}
const api={render};
if(typeof module!=="undefined"&&module.exports)module.exports=api;
root.PowerOpsNetworkAlerts=api;
})(typeof window!=="undefined"?window:globalThis);
