const test = require('node:test');
const assert = require('node:assert/strict');
const { runSynthetic, reconcile } = require('../src/reconciliation.js');

test('synthetic reconciliation produces stable counts and values', () => {
  const result = runSynthetic();
  assert.equal(result.summary.billingRecords, 6);
  assert.equal(result.summary.paymentRecords, 9);
  assert.equal(result.summary.matchedBills, 3);
  assert.equal(result.summary.matchedAmount, 450000);
  assert.equal(result.summary.exceptionCount, 4);
});

test('split payments are aggregated and can match a bill exactly', () => {
  const result = runSynthetic();
  assert.ok(result.matched.some(x => x.reference === 'REF-002' && x.paid === 150000));
});

test('duplicate, partial, unmatched and reversal candidates are classified', () => {
  const result = runSynthetic();
  const classes = new Set(result.exceptions.map(x => x.type));
  for (const expected of ['DUPLICATE_CANDIDATE', 'PARTIAL', 'UNMATCHED_PAYMENT', 'REVERSAL']) assert.ok(classes.has(expected));
});

test('same fixture and rule version produce identical results', () => {
  assert.deepEqual(runSynthetic(), runSynthetic());
});

test('invalid and duplicate record identifiers fail closed', () => {
  assert.throws(() => reconcile([{bill_id:'B1',account_id:'A1',payment_reference:'R1',amount:-1,currency:'NGN'}], []), /Invalid billing row/);
  const bills = [{bill_id:'B1',account_id:'A1',payment_reference:'R1',amount:100,currency:'NGN'},{bill_id:'B1',account_id:'A2',payment_reference:'R2',amount:100,currency:'NGN'}];
  assert.throws(() => reconcile(bills, []), /Duplicate billing record ID/);
});
