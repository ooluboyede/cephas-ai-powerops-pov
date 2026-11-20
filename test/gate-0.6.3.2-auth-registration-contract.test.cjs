"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
// Reference contract model only; not evidence of a patched PostgreSQL server.
function dispatch(s,message,commitRegistration,executeUserCode){
 if(!s.registrationCommitted){if(s.userTransactionOpen)throw new Error("registration must precede user transaction");if(!commitRegistration()){s.terminated=true;throw new Error("registration commit failed");}s.registrationCommitted=true;s.registrationCommitSequence=++s.sequence;}
 if(!s.registrationCommitted||s.terminated)throw new Error("user message blocked");
 return executeUserCode(message,++s.sequence);
}
test("first Q BEGIN commits registration before user transaction",()=>{const s={registrationCommitted:false,userTransactionOpen:false,sequence:0},order=[];dispatch(s,"Q:BEGIN",()=>{order.push("registration-commit");return true;},()=>{order.push("user-BEGIN");s.userTransactionOpen=true;});assert.deepEqual(order,["registration-commit","user-BEGIN"]);assert.ok(s.registrationCommitSequence<s.sequence);});
test("first ROLLBACK cannot roll back registration",()=>{const s={registrationCommitted:false,userTransactionOpen:false,sequence:0};dispatch(s,"Q:ROLLBACK",()=>true,()=>{s.userTransactionOpen=false;});assert.equal(s.registrationCommitted,true);});
test("first E and F are gated before portal execution or function invocation",()=>{for(const m of ["E:EXECUTE","F:FUNCTIONCALL"]){const s={registrationCommitted:false,userTransactionOpen:false,sequence:0};let called=false;dispatch(s,m,()=>true,()=>{called=true;});assert.equal(called,true);assert.equal(s.registrationCommitted,true);}});
test("P and B parse/bind paths are gated before user SQL processing",()=>{for(const m of ["P:PARSE","B:BIND"]){const s={registrationCommitted:false,userTransactionOpen:false,sequence:0};let called=false;dispatch(s,m,()=>true,()=>{called=true;});assert.equal(called,true);assert.equal(s.registrationCommitted,true);}});
test("registration failure terminates backend and never dispatches user code",()=>{const s={registrationCommitted:false,userTransactionOpen:false,sequence:0};let called=false;assert.throws(()=>dispatch(s,"Q:SELECT 1",()=>false,()=>{called=true;}));assert.equal(called,false);assert.equal(s.terminated,true);});
test("user-command abort leaves separately committed registration intact",()=>{const s={registrationCommitted:false,userTransactionOpen:false,sequence:0};assert.throws(()=>dispatch(s,"Q:SELECT failing_function()",()=>true,()=>{throw Error("user command aborted");}));assert.equal(s.registrationCommitted,true);});
