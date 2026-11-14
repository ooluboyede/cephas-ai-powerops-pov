(function(root){
"use strict";
const records=new Map();
function seed(alerts){alerts.forEach(a=>{if(!records.has(a.entity_id))records.set(a.entity_id,{entity_id:a.entity_id,status:"New",assigned_to:"Unassigned",history:[{action:"Generated",at:"2026-10-31T23:59:00Z",note:"Synthetic ML alert created"}]})});return list()}
function list(){return Array.from(records.values()).map(x=>JSON.parse(JSON.stringify(x)))}
function update(id,action,value){
 const item=records.get(id);if(!item)throw new Error("Unknown alert");
 if(action==="assign"){if(!String(value||"").trim())throw new Error("Assignee is required");item.assigned_to=String(value).trim()}
 else if(action==="acknowledge")item.status="Acknowledged";
 else if(action==="escalate")item.status="Escalation recommended";
 else if(action==="close"){if(!String(value||"").trim())throw new Error("A closure reason is mandatory");item.status="Closed"}
 else throw new Error("Unsupported triage action");
 item.history.push({action,at:"SIMULATED_SESSION_TIME",note:action==="close"?String(value):String(value||"")});
 return JSON.parse(JSON.stringify(item));
}
const api={seed,list,update};
if(typeof module!=="undefined"&&module.exports)module.exports=api;
root.PowerOpsTriage=api;
})(typeof window!=="undefined"?window:globalThis);
