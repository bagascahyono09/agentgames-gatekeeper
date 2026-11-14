# Wildcard entry — GATEWARDEN, a wallet & transaction guard

**Use case.** Every wallet and payment system faces the same question GATEWARDEN
answers: *should this proof-backed payment request be allowed through?* A
cryptographic proof can be perfectly valid and still back the wrong payment —
wrong recipient, wrong verification key, an expired condition, an amount above
the agreed cap, or a proof that was already spent once. GATEWARDEN is the
guard that checks the *statement*, not just the proof.

**What it does.** GATEWARDEN runs as a public HTTPS endpoint. For each incoming
request it deterministically verifies seven things — verification-key match,
threshold, expiry, recipient, transfer cap, and proof freshness — then returns
a signed APPROVE/REJECT decision with a machine-readable reason code, plus a
Groth16 zero-knowledge proof that the decision followed the rule. The proof is
generated locally with snarkjs against the event's registered gatekeeper
circuit, whose own constraints assert the same rule, so the guard cannot fake
a decision: the circuit is the referee.

**Why it matters beyond the game.** This is the reference shape of a
transaction firewall for agent wallets: an autonomous agent that can move
money needs a gate that (1) fails closed, (2) explains every rejection with a
reason code, (3) never lets a probabilistic model make the final call, and
(4) produces verifiable evidence of each decision for later audit. GATEWARDEN
implements all four, end-to-end, on a small shared VM — median end-to-end
latency ~0.3 s per decision including proving, against a 60-second budget.

**Live artefacts.**
- Endpoint: a public HTTPS agent endpoint (registered on the Agent Games
  dashboard; health check and signed preflight pass).
- Code: this repository — endpoint, decision engine, prover, persistence,
  and a test harness that replays every documented trap category.
- Competition record: Proof Gatekeeper rounds (decisions and proofs are
  recorded on the public event ledger).
