"use strict";
const crypto=require("node:crypto");
const {canonical,sha256,verifyModelManifest}=require("./ml-governance.js");

const DEFAULT_POLICY=Object.freeze({
 requiredApprovalRoles:["model-risk","security","operations-owner"],
 requireDistinctApprovers:true,
 requireArtifactVerification:true,
 requirePromotionEligibility:true
});
function assert(ok,message){if(!ok)throw new Error(message)}
function text(v,name){assert(typeof v==="string"&&v.trim().length>0,name+" is required")}
function hash(value){return crypto.createHash("sha256").update(canonical(value)).digest("hex")}
function createRegistry({policy=DEFAULT_POLICY,registryId="POWEROPS-DEMO-REGISTRY-V1"}={}){
 text(registryId,"registryId");
 const state={schemaVersion:"1.0",registryId,policy:{...policy,requiredApprovalRoles:policy.requiredApprovalRoles.slice()},events:[],candidates:{},releases:[],activeReleaseId:null};
 function append(type,payload,actorId){
  text(actorId,"actorId");
  const previousHash=state.events.length?state.events[state.events.length-1].eventHash:"GENESIS";
  const descriptor={sequence:state.events.length+1,type,payload,actorId,previousHash};
  const event=Object.freeze({...descriptor,eventHash:hash(descriptor)});
  state.events.push(event);
  return event;
 }
 function registerCandidate(input){
  assert(input&&input.manifest,"Model manifest is required");
  const integrity=verifyModelManifest(input.manifest);
  assert(integrity.valid,"Cannot register a model with an invalid manifest");
  text(input.candidateId,"candidateId");text(input.createdBy,"createdBy");
  text(input.artifactSha256,"artifactSha256");
  assert(/^[a-f0-9]{64}$/.test(input.artifactSha256),"Artifact SHA-256 must be a 64-character lowercase hex digest");
  assert(input.artifactVerification&&input.artifactVerification.verified===true,"Trusted artifact verification receipt is required");
  assert(input.artifactVerification.artifactSha256===input.artifactSha256,"Artifact verification receipt hash mismatch");
  text(input.artifactVerification.publisherKeyId,"publisherKeyId");
  text(input.artifactVerification.verifierVersion,"verifierVersion");
  assert(!state.candidates[input.candidateId],"Candidate ID already exists");
  const candidate={candidateId:input.candidateId,modelVersion:input.manifest.modelVersion,manifestSha256:input.manifest.manifestSha256,artifactSha256:input.artifactSha256,createdBy:input.createdBy,createdAt:input.createdAt||null,eligibility:input.eligibility||{eligible:false,reasons:["No promotion eligibility decision supplied"]},artifactVerification:{verified:true,artifactSha256:input.artifactSha256,publisherKeyId:input.artifactVerification.publisherKeyId,verifierVersion:input.artifactVerification.verifierVersion,verifiedAt:input.artifactVerification.verifiedAt||null},approvals:[],status:"candidate"};
  state.candidates[input.candidateId]=candidate;
  append("candidate-registered",{candidateId:candidate.candidateId,modelVersion:candidate.modelVersion,manifestSha256:candidate.manifestSha256,artifactSha256:candidate.artifactSha256,createdBy:candidate.createdBy},"registry-service");
  return snapshotCandidate(candidate);
 }
 function snapshotCandidate(c){return JSON.parse(JSON.stringify(c))}
 function approveCandidate({candidateId,approvalId,approverId,role,decision="approve",reason}){
  const c=state.candidates[candidateId];assert(c,"Unknown model candidate");
  text(approvalId,"approvalId");text(approverId,"approverId");text(role,"role");text(reason,"reason");
  assert(c.status==="candidate","Only a candidate can receive release approvals");
  assert(state.policy.requiredApprovalRoles.includes(role),"Approver role is not in the release policy");
  assert(decision==="approve"||decision==="reject","Approval decision must be approve or reject");
  assert(!c.approvals.some(a=>a.approvalId===approvalId),"Approval ID already exists");
  if(state.policy.requireDistinctApprovers){
   assert(approverId!==c.createdBy,"Model creator cannot approve their own candidate");
   assert(!c.approvals.some(a=>a.approverId===approverId),"Approver must be distinct for each required role");
  }
  assert(!c.approvals.some(a=>a.role===role),"An approval decision already exists for this role");
  const approval={approvalId,approverId,role,decision,reason,recordedAt:null};
  c.approvals.push(approval);
  append("release-approval-recorded",{candidateId,approvalId,approverId,role,decision,reason},"approval-service");
  if(decision==="reject")c.status="rejected";
  return snapshotCandidate(c);
 }
 function promoteCandidate({candidateId,releaseId,actorId}){
  const c=state.candidates[candidateId];assert(c,"Unknown model candidate");
  text(releaseId,"releaseId");text(actorId,"actorId");
  assert(c.status==="candidate","Candidate is not in a promotable state");
  if(state.policy.requirePromotionEligibility)assert(c.eligibility&&c.eligibility.eligible===true,"Promotion eligibility is blocked or missing");
  if(state.policy.requireArtifactVerification)assert(c.artifactVerification&&c.artifactVerification.verified===true,"Artifact verification is missing");
  const rejected=c.approvals.some(a=>a.decision==="reject");
  assert(!rejected,"A rejected candidate cannot be promoted");
  const approvedRoles=new Set(c.approvals.filter(a=>a.decision==="approve").map(a=>a.role));
  const missing=state.policy.requiredApprovalRoles.filter(role=>!approvedRoles.has(role));
  assert(missing.length===0,"Required independent approvals missing: "+missing.join(", "));
  assert(!state.releases.some(r=>r.releaseId===releaseId),"Release ID already exists");
  const release={releaseId,candidateId,modelVersion:c.modelVersion,manifestSha256:c.manifestSha256,artifactSha256:c.artifactSha256,approvedRoles:Array.from(approvedRoles).sort(),releasedBy:actorId,previousReleaseId:state.activeReleaseId,status:"released"};
  state.releases.push(release);state.activeReleaseId=releaseId;c.status="released";
  append("model-release-activated",{...release},"release-service");
  return JSON.parse(JSON.stringify(release));
 }
 function rollback({targetReleaseId,actorId,reason}){
  text(targetReleaseId,"targetReleaseId");text(actorId,"actorId");text(reason,"reason");
  const target=state.releases.find(r=>r.releaseId===targetReleaseId);
  assert(target,"Rollback target must be a previously approved release");
  assert(state.activeReleaseId&&state.activeReleaseId!==targetReleaseId,"Rollback target must differ from the active release");
  const previous=state.activeReleaseId;
  state.activeReleaseId=targetReleaseId;
  append("model-release-rolled-back",{fromReleaseId:previous,toReleaseId:targetReleaseId,reason,requiresPostRollbackReview:true},"rollback-service");
  return {activeReleaseId:state.activeReleaseId,rolledBackFrom:previous,rolledBackTo:targetReleaseId,requiresPostRollbackReview:true};
 }
 function verifyEventChain(){
  let previousHash="GENESIS";
  for(let i=0;i<state.events.length;i++){
   const event=state.events[i],{eventHash,...descriptor}=event;
   if(event.sequence!==i+1||event.previousHash!==previousHash||hash(descriptor)!==eventHash)return {valid:false,failedSequence:i+1};
   previousHash=eventHash;
  }
  return {valid:true,eventCount:state.events.length,headHash:previousHash};
 }
 function getSnapshot(){
  return JSON.parse(JSON.stringify({schemaVersion:state.schemaVersion,registryId:state.registryId,policy:state.policy,candidates:state.candidates,releases:state.releases,activeReleaseId:state.activeReleaseId,events:state.events,chainVerification:verifyEventChain()}));
 }
 return Object.freeze({registerCandidate,approveCandidate,promoteCandidate,rollback,verifyEventChain,getSnapshot});
}
module.exports={DEFAULT_POLICY,createRegistry};
