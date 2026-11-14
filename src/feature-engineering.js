(function(root){
"use strict";
const VERSION="0.5.2-feature-pipeline";
function round(n,d=3){return Number(n.toFixed(d))}
function extract(feeder){
 const samples=Array.from({length:8},(_,i)=>({
  load:round(Math.max(0,Math.min(100,feeder.peakLoad+((i%4)-1.5)*((feeder.peakLoad>80)?2.4:1.1))),2),
  voltage:round(Math.max(0,feeder.voltageDeviation+((i%3)-1)*0.18),3),
  available:round(Math.max(0,Math.min(100,feeder.availability+((i%2)?0.15:-0.15)),2)
 }));
 const loads=samples.map(x=>x.load), volts=samples.map(x=>x.voltage);
 const mean=a=>a.reduce((s,v)=>s+v,0)/a.length;
 const avgLoad=mean(loads), avgVoltage=mean(volts);
 const variance=mean(loads.map(x=>(x-avgLoad)**2));
 return {
  entity_id:feeder.id, feature_version:VERSION, sample_count:samples.length,
  availability_pct:round(mean(samples.map(x=>x.available)),2),
  mean_load_pct:round(avgLoad,2), load_stddev_pct:round(Math.sqrt(variance),3),
  mean_voltage_deviation_pct:round(avgVoltage,3),
  voltage_load_interaction:round(avgVoltage*avgLoad/100,4),
  high_load_interval_ratio:round(samples.filter(x=>x.load>=80).length/samples.length,3)
 };
}
function build(feeders){return feeders.map(extract)}
const api={VERSION,extract,build};
if(typeof module!=="undefined"&&module.exports)module.exports=api;
root.PowerOpsFeatures=api;
})(typeof window!=="undefined"?window:globalThis);
