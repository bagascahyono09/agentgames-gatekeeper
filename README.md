# GATEWARDEN — a Proof Gatekeeper agent for the zkVerify Agent Games

GATEWARDEN is a **wallet & transaction guard**: a public HTTPS endpoint that
receives proof-backed payment requests from the Agent Games platform, decides
**APPROVE** or **REJECT** with a deterministic rules engine, and writes its own
Groth16 zero-knowledge proof of every decision — so anyone can verify the
guard followed the rule without seeing how it is operated.

Built by [@bagasdc](https://agentgames.zkverify.io) for the **Proof Gatekeeper**
event (and entered in **Wildcard** as a working wallet/transaction guard).

## The decision rule (fail-closed)

A request is approved only when **every** check passes — one mismatch is a
rejection:

| Check | Rejection reason |
| --- | --- |
| Proof's verification key ≠ the registered condition VK | `VK_SUBSTITUTION` |
| Public balance below the condition minimum | `THRESHOLD_MISMATCH` |
| Condition expired (`current_block >= expiry_block`) | `EXPIRED_CONDITION` |
| Recipient ≠ the condition's recipient | `RECIPIENT_MISMATCH` |
| Amount above the single-transfer cap | `AMOUNT_OVERFLOW` |
| Proof reference already accepted in an earlier task | `PROOF_REUSED` |
| All checks pass | `VALID_CONDITION` → APPROVE |

The same rule is enforced twice: once in the agent's deterministic engine and
once inside the gatekeeper Circom circuit itself, whose constraints assert
`decision == 1` exactly when all field checks pass. The agent generates a
Groth16 proof (snarkjs, BN128) locally for every provable decision and returns
it with the signed response; `PROOF_REUSED` rejections carry no proof, per the
event rules. Decisions are never made by a language model — the final call is
deterministic code, and any internal error degrades to a signed rejection or a
proof-less decision, never to a default approval.

## Protocol

- `POST /agent` — tasks arrive as signed JSON envelopes
  (`x-agent-games-signature` = HMAC-SHA256 over the raw body; verified before
  parsing, compared in constant time). Every response is signed the same way.
- Preflight envelopes (`agent-games.preflight.v1`) are answered with
  `{ "ok": true, "protocolVersion": "v1" }`, signed.
- Task responses: `{ decision, reason_code, proof_tx, proof, public_signals }`.
- Task IDs are idempotent: a re-delivered task returns the cached response,
  and the proof-reference seen-set is persisted on disk across restarts.
- Measured on a small shared VM (1.5 vCPU): **~0.3 s median end-to-end** per
  task including local proving — far inside the 60-second hard deadline.

## Run it

```bash
npm install
cp .env.example agent.env   # fill AGENT_GAMES_HMAC_SECRET from the dashboard
# download the circuit artifacts from the platform:
#   /circuits/gatekeeper.wasm and /circuits/gatekeeper_final.zkey
#   into ../circuits/ (or adjust prover.mjs paths)
node server.mjs
node test.mjs   # local harness: replays every trap category + timing
```

Secrets are loaded from the environment only (`AGENT_GAMES_HMAC_SECRET`, and
optionally `KURIER_API_KEY` for the on-chain audit-trail submission via
Kurier). No secret is ever logged or committed.

## Layout

- `server.mjs` — HTTP endpoint, HMAC verification/signing, task pipeline
- `engine.mjs` — the deterministic 7-category decision engine
- `prover.mjs` — circuit input encodings + snarkjs proving + self-verification
- `store.mjs` — on-disk seen-set and response cache (atomic writes)
- `kurier.mjs` — optional Kurier submission (non-blocking audit trail)
- `test.mjs` — self-contained test harness with sample envelopes
