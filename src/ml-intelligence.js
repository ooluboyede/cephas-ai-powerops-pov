(function(root){
"use strict";
const VERSION="0.5.2-knn-novelty-1";
const KEYS=["availability_pct","mean_load_pct","load_stddev_pct","mean_voltage_deviation_pct","voltage_load_interaction","high_load_interval_ratio"];
const BASELINE=[
 {availability_pct:98.4,mean_load_pct:61,load_stddev_pct:1.1,mean_voltage_deviation_pct:0.8,voltage_load_interaction:0.49,high_load_interval_ratio:0},
 {availability_pct:98.1,mean_load_pct:65,load_stddev_pct:1.3,mean_voltage_deviation_pct:1.1,voltage_load_interaction:0.72,high_load_interval_ratio:0},
 {availability_pct:97.8,mean_load_pct:69,load_stddev_pct:1.2,mean_voltage_deviation_pct:1.3,voltage_load_interaction:0.90,high_load_interval_ratio:0},
 {availability_pct:97.5,mean_load_pct:72,load_stddev_pct:1.5,mean_voltage_deviation_pct:1.4,voltage_load_interaction:1.01,high_load_interval_ratio:0},
 {availability_pct:97.2,mean_load_pct:74,load_stddev_pct:1.4,mean_voltage_deviation_pct:1.6,voltage_load_interaction:1.18,high_load_interval_ratio:0},
 {availability_pct:96.9,mean_load_pct:68,load_stddev_pct:1.0,mean_voltage_deviation_pct:1.2,voltage_load_interaction:0.82,high_load_interval_ratio:0}
];
const MEDIANS={availability_pct:97.55,mean_load_pct:68.5,load_stddev_pct:1.25,mean_voltage_deviation_pct:1.25,voltage_load_interaction:0.86,high_load_interval_ratio:0};
const SCALES={availability_pct:1.2,mean_load_pct:8,load_stddev_pct:0.8,mean_voltage_deviation_pct:0.9,voltage_load_interaction:0.9,high_load_interval_ratio:0.35};
const distance=(a,b)=>Math.sqrt(KEYS.reduce((s,k)=>s+(((a[k]-b[k])/SCALES[k])**2),0)/KEYS.length);
function score(feature){
 const nearest=BASELINE.map(row=>distance(feature,row)).sort((a,b)=>a-b).slice(0,3);
 const d=nearest.reduce((s,x)=>s+x,0)/nearest.length;
 const score=Math.max(0,Math.min(100,Math.round(d*38)));
 const contributors=KEYS.map(k=>({feature:k,deviation:Number(Math.abs(feature[k]-MEDIANS[k]).toFixed(3)),direction:feature[k]>=MEDIANS[k]?"above":"below",weight:Number((Math.abs(feature[k]-MEDIANS[k])/SCALES[k]).toFixed(3))})).sort((a,b)=>b.weight-a.weight).slice(0,3);
 return {entity_id:feature.entity_id,model_version:VERSION,anomaly_score:score,band:score>=65?"High":score>=35?"Elevated":"Normal",nearest_reference_distance:Number(d.toFixed(4)),confidence_label:"Exploratory synthetic-data score; not a calibrated probability",explanations:contributors,feature_version:feature.feature_version};
}
function infer(features){return features.map(score)}
function evaluate(){
 const benchmark=[
  {label:"normal",feature:{availability_pct:98.1,mean_load_pct:66,load_stddev_pct:1.2,mean_voltage_deviation_pct:1.1,voltage_load_interaction:0.73,high_load_interval_ratio:0}},
  {label:"normal",feature:{availability_pct:97.4,mean_load_pct:73,load_stddev_pct:1.4,mean_voltage_deviation_pct:1.5,voltage_load_interaction:1.1,high_load_interval_ratio:0}},
  {label:"anomaly",feature:{availability_pct:91,mean_load_pct:94,load_stddev_pct:5.8,mean_voltage_deviation_pct:6.2,voltage_load_interaction:5.83,high_load_interval_ratio:1}},
  {label:"anomaly",feature:{availability_pct:93,mean_load_pct:89,load_stddev_pct:4.7,mean_voltage_deviation_pct:4.8,voltage_load_interaction:4.27,high_load_interval_ratio:0.75}}
 ];
 let tp=0,tn=0,fp=0,fn=0;
 benchmark.forEach(x=>{const predicted=score(x.feature).anomaly_score>=35;if(predicted&&x.label==="anomaly")tp++;else if(predicted)fp++;else if(x.label==="normal")tn++;else fn++});
 return {benchmark_cases:benchmark.length,true_positive:tp,true_negative:tn,false_positive:fp,false_negative:fn,precision:tp+fp?Number((tp/(tp+fp)).toFixed(3)):0,recall:tp+fn?Number((tp/(tp+fn)).toFixed(3)):0,scope:"Tiny deterministic synthetic benchmark only; not a field-performance estimate"};
}
const api={VERSION,KEYS,score,infer,evaluate,baselineSize:BASELINE.length};
if(typeof module!=="undefined"&&module.exports)module.exports=api;
root.PowerOpsML=api;
})(typeof window!=="undefined"?window:globalThis);
