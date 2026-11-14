// Deterministic decision engine for Proof Gatekeeper tasks.
// Mirrors the gatekeeper circuit semantics exactly (verified against the
// circuit's own asserts on this machine, 2026-11-15):
//   decision = 1 (APPROVE) iff ALL of:
//     proof_vk == registered_vk, public_balance >= minimum,
//     current_block < expiry_block, recipient == condition_recipient,
//     amount <= max_transfer, and proof_tx not seen before.
// Trap checks run in a fixed order; tasks are generated with a single trap.

export const REASONS = {
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  AMOUNT: "AMOUNT_OVERFLOW",
  REUSED: "PROOF_REUSED",
};

const norm = (v) => String(v ?? "").trim().toLowerCase();

function big(v, field) {
  // Amounts/blocks arrive as decimal strings in the task envelope.
  try {
    return BigInt(v);
  } catch {
    throw new Error(`field ${field} is not an integer: ${v}`);
  }
}

// seenHas(proofTxLower) -> bool : whether this proof ref appeared in an EARLIER task.
export function decide(input, seenHas) {
  if (norm(input.proof_vk) !== norm(input.registered_vk)) {
    return { decision: "REJECT", reason_code: REASONS.VK, needsProof: true };
  }
  if (big(input.public_balance, "public_balance") < big(input.minimum, "minimum")) {
    return { decision: "REJECT", reason_code: REASONS.THRESHOLD, needsProof: true };
  }
  if (big(input.current_block, "current_block") >= big(input.expiry_block, "expiry_block")) {
    return { decision: "REJECT", reason_code: REASONS.EXPIRED, needsProof: true };
  }
  if (norm(input.recipient) !== norm(input.condition_recipient)) {
    return { decision: "REJECT", reason_code: REASONS.RECIPIENT, needsProof: true };
  }
  if (big(input.amount, "amount") > big(input.max_transfer, "max_transfer")) {
    return { decision: "REJECT", reason_code: REASONS.AMOUNT, needsProof: true };
  }
  if (seenHas(norm(input.proof_tx))) {
    // Per the event rules: PROOF_REUSED tasks have no proof to submit.
    return { decision: "REJECT", reason_code: REASONS.REUSED, needsProof: false };
  }
  return { decision: "APPROVE", reason_code: REASONS.VALID, needsProof: true };
}
