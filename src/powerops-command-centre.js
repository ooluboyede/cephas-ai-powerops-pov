(function(root){
"use strict";
const snapshot = Object.freeze({
  label:"SYNTHETIC DEMONSTRATION DATA",
  generatedFor:"IBEDC-first PowerOps PoV",
  metrics:[
    {label:"Feeder availability",value:"96.8%",note:"Illustrative service availability"},
    {label:"Active network alerts",value:"7",note:"Signals awaiting operator review"},
    {label:"Assets requiring attention",value:"12",note:"Condition-monitoring demo records"},
    {label:"Open service requests",value:"184",note:"Synthetic customer-service queue"}
  ],
  modules:[
    {id:"network",name:"Network operations",status:"Planned",detail:"Feeder, transformer and network performance intelligence"},
    {id:"outage",name:"Outage & fault intelligence",status:"Planned",detail:"Outage visibility, fault clustering and restoration support"},
    {id:"assets",name:"Asset health & maintenance",status:"Planned",detail:"Asset registry, condition indicators and maintenance prioritisation"},
    {id:"metering",name:"Metering & energy intelligence",status:"Planned",detail:"Meter data quality, consumption patterns and energy balance"},
    {id:"customer",name:"Customer operations",status:"Planned",detail:"Service requests, complaints and service-level monitoring"},
    {id:"workforce",name:"Field workforce",status:"Planned",detail:"Work orders, crew coordination and field evidence"},
    {id:"revenue",name:"Revenue Assurance",status:"Initial module slice",detail:"Synthetic findings, investigations and payment reconciliation",page:"overview"},
    {id:"planning",name:"Forecasting & planning",status:"Planned",detail:"Load forecasting, demand scenarios and operational planning"}
  ],
  alerts:[
    {severity:"High",title:"Feeder load variance",detail:"Synthetic feeder IB-NORTH-04 is above its illustrative planning threshold.",action:"Validate telemetry and operating context"},
    {severity:"Medium",title:"Transformer condition review",detail:"Two synthetic asset records have elevated condition indicators.",action:"Review inspection history and maintenance priority"},
    {severity:"Medium",title:"Service request backlog",detail:"A synthetic service area has an aged customer-request queue.",action:"Review allocation and service-level ageing"}
  ],
  feeders:[
    {id:"IB-NORTH-04",area:"Ibadan North",availability:"94.2%",load:"87%",attention:"Operator review"},
    {id:"IB-SOUTH-02",area:"Ibadan South",availability:"98.1%",load:"72%",attention:"Normal"},
    {id:"AKY-01",area:"Akinyele",availability:"96.7%",load:"79%",attention:"Normal"},
    {id:"OGB-03",area:"Ogbomosho",availability:"95.4%",load:"83%",attention:"Monitor"}
  ]
});
function getSnapshot(){return JSON.parse(JSON.stringify(snapshot))}
function element(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=text;return node}
function render(){
 if(!root.document)return;
 const data=getSnapshot();
 const kpis=root.document.getElementById("powerops-kpis");
 const modules=root.document.getElementById("powerops-modules");
 const alerts=root.document.getElementById("powerops-alerts");
 const feeders=root.document.getElementById("powerops-feeders");
 if(!kpis||!modules||!alerts||!feeders)return;
 kpis.replaceChildren();data.metrics.forEach(m=>{const card=element("div","card");card.append(element("div","klabel",m.label),element("div","kvalue",m.value),element("div","kmeta",m.note));kpis.append(card)});
 modules.replaceChildren();data.modules.forEach(m=>{const card=element("div","field");const row=element("div");row.style.display="flex";row.style.justifyContent="space-between";row.style.gap="8px";row.append(element("strong","",m.name),element("span","tag",m.status));card.append(row,element("p","muted",m.detail));if(m.page){const button=element("button","linkbtn","Open module →");button.type="button";button.addEventListener("click",()=>root.navigate(m.page));card.append(button)}modules.append(card)});
 alerts.replaceChildren();data.alerts.forEach(a=>{const item=element("div","field");item.style.marginBottom="9px";item.append(element("span","tag "+(a.severity==="High"?"high":"medium"),a.severity),element("strong","",a.title),element("p","muted",a.detail),element("p","",a.action));alerts.append(item)});
 feeders.replaceChildren();data.feeders.forEach(f=>{const tr=element("tr");[f.id,f.area,f.availability,f.load,f.attention].forEach(v=>tr.append(element("td","",v)));feeders.append(tr)});
}
const api={getSnapshot,render};
if(typeof module!=="undefined"&&module.exports)module.exports=api;
if(root)root.PowerOpsCommandCentre=api;
})(typeof window!=="undefined"?window:globalThis);
