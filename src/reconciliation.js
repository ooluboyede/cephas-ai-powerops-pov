(function(root){
  "use strict";
  const RULE_VERSION = "RA-RECON-1.0.0";
  const INPUT_SNAPSHOT = "IBEDC-SYNTHETIC-OCT-2026-V1";
  const billing = [
    {bill_id:"BILL-001",account_id:"AC-SYN-001",payment_reference:"REF-001",amount:100000,currency:"NGN"},
    {bill_id:"BILL-002",account_id:"AC-SYN-002",payment_reference:"REF-002",amount:150000,currency:"NGN"},
    {bill_id:"BILL-003",account_id:"AC-SYN-003",payment_reference:"REF-003",amount:200000,currency:"NGN"},
    {bill_id:"BILL-004",account_id:"AC-SYN-004",payment_reference:"REF-004",amount:120000,currency:"NGN"},
    {bill_id:"BILL-005",account_id:"AC-SYN-005",payment_reference:"REF-005",amount:80000,currency:"NGN"},
    {bill_id:"BILL-006",account_id:"AC-SYN-006",payment_reference:"REF-006",amount:60000,currency:"NGN"}
  ];
  const payments = [
    {payment_id:"PAY-001",payment_reference:"REF-001",amount:100000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-002",payment_reference:"REF-002",amount:70000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-003",payment_reference:"REF-002",amount:80000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-004",payment_reference:"REF-003",amount:200000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-005",payment_reference:"REF-004",amount:120000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-006",payment_reference:"REF-004",amount:120000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-007",payment_reference:"REF-005",amount:50000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-008",payment_reference:"REF-007",amount:40000,currency:"NGN",status:"posted"},
    {payment_id:"PAY-009",payment_reference:"REF-006",amount:60000,currency:"NGN",status:"reversed"}
  ];
  function validate(bills, rows) {
    if (!Array.isArray(bills) || !Array.isArray(rows)) throw new TypeError("Billing and payment inputs must be arrays");
    const ids = new Set();
    for (const row of bills) {
      if (!row || !row.bill_id || !row.payment_reference || !row.account_id || !Number.isSafeInteger(row.amount) || row.amount < 0 || !row.currency) throw new TypeError("Invalid billing row");
      if (ids.has("B:"+row.bill_id)) throw new TypeError("Duplicate billing record ID");
      ids.add("B:"+row.bill_id);
    }
    for (const row of rows) {
      if (!row || !row.payment_id || !row.payment_reference || !Number.isSafeInteger(row.amount) || row.amount < 0 || !row.currency || !["posted","reversed"].includes(row.status)) throw new TypeError("Invalid payment row");
      if (ids.has("P:"+row.payment_id)) throw new TypeError("Duplicate payment record ID");
      ids.add("P:"+row.payment_id);
    }
  }
  function reconcile(bills, rows) {
    validate(bills, rows);
    const groups = new Map();
    rows.forEach(row => {
      if (!groups.has(row.payment_reference)) groups.set(row.payment_reference, []);
      groups.get(row.payment_reference).push(row);
    });
    const exceptions = [], matched = [];
    const seenRefs = new Set();
    for (const bill of bills) {
      seenRefs.add(bill.payment_reference);
      const group = groups.get(bill.payment_reference) || [];
      const currencies = new Set([bill.currency, ...group.map(p => p.currency)]);
      if (currencies.size > 1) {
        exceptions.push({type:"CURRENCY_MISMATCH",reference:bill.payment_reference,amount:bill.amount,explanation:"Billing and payment currencies differ; quarantined from amount comparison."});
        continue;
      }
      const reversed = group.filter(p => p.status === "reversed");
      const posted = group.filter(p => p.status === "posted");
      const duplicateAmounts = new Set();
      let duplicate = false;
      for (const p of posted) {
        if (duplicateAmounts.has(p.amount)) duplicate = true;
        duplicateAmounts.add(p.amount);
      }
      if (duplicate) {
        exceptions.push({type:"DUPLICATE_CANDIDATE",reference:bill.payment_reference,amount:posted.reduce((s,p)=>s+p.amount,0),explanation:"Multiple posted rows share the same reference and amount; finance confirmation is required."});
      } else if (posted.length === 0 && reversed.length > 0) {
        exceptions.push({type:"REVERSAL",reference:bill.payment_reference,amount:reversed.reduce((s,p)=>s+p.amount,0),explanation:"The source contains a reversal and no active posted payment for this bill."});
      } else if (posted.length === 0) {
        exceptions.push({type:"UNPAID",reference:bill.payment_reference,amount:bill.amount,explanation:"No posted payment was found for this billing reference."});
      } else {
        const paid = posted.reduce((s,p)=>s+p.amount,0);
        if (paid === bill.amount) matched.push({bill_id:bill.bill_id,reference:bill.payment_reference,billed:bill.amount,paid});
        else if (paid < bill.amount) exceptions.push({type:"PARTIAL",reference:bill.payment_reference,amount:bill.amount-paid,explanation:"Posted payments are below the billed amount; residual requires allocation review."});
        else exceptions.push({type:"OVERPAYMENT",reference:bill.payment_reference,amount:paid-bill.amount,explanation:"Posted payments exceed the bill amount; allocation and duplicate checks are required."});
      }
      if (reversed.length && posted.length) exceptions.push({type:"REVERSAL_WITH_POSTED",reference:bill.payment_reference,amount:reversed.reduce((s,p)=>s+p.amount,0),explanation:"A reversal row coexists with posted rows; inspect transaction chronology before disposition."});
    }
    for (const [reference, group] of groups) {
      if (!seenRefs.has(reference)) exceptions.push({type:"UNMATCHED_PAYMENT",reference,amount:group.filter(p=>p.status==="posted").reduce((s,p)=>s+p.amount,0),explanation:"Payment reference has no corresponding billing record in this input snapshot."});
    }
    return {
      ruleVersion:RULE_VERSION,
      inputSnapshot:INPUT_SNAPSHOT,
      summary:{billingRecords:bills.length,paymentRecords:rows.length,matchedBills:matched.length,matchedAmount:matched.reduce((s,x)=>s+x.paid,0),exceptionCount:exceptions.length},
      matched,exceptions
    };
  }
  function runSynthetic(){return reconcile(billing,payments);}
  const api={RULE_VERSION,INPUT_SNAPSHOT,reconcile,runSynthetic};
  if (typeof module !== "undefined" && module.exports) module.exports=api;
  if (root) root.PowerOpsReconciliation=api;
})(typeof window !== "undefined" ? window : globalThis);
