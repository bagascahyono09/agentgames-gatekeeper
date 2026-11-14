// Local harness: boots the server with a throwaway secret, replays sample
// envelopes for every trap category, checks decisions + proof validity + timing.
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const PORT = 8899;
const SECRET = "test-secret-for-local-harness";
const DATA = "/tmp/agentgames-test-data";
fs.rmSync(DATA, { recursive: true, force: true });
fs.mkdirSync(DATA, { recursive: true });

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x13aa24c0ffee2540102030405060708090a0b0c0d0e0f101112131415161718";
const ADDR = "0xDe42aBcDeF00112233445566778899001122339f01";
const ADDR2 = "0x1111111111111111111111111111111111111111";

let n = 0;
function task(mut = {}) {
  n += 1;
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: `gk_test_${n}`,
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xtx" + n.toString(16).padStart(8, "0"),
      ...mut,
    },
  };
}

function sign(raw) {
  return createHmac("sha256", SECRET).update(raw).digest("hex");
}
async function post(obj, { badSig = false } = {}) {
  const raw = JSON.stringify(obj);
  const t0 = Date.now();
  const r = await fetch(`http://127.0.0.1:${PORT}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": badSig ? "deadbeef" : sign(raw) },
    body: raw,
  });
  const text = await r.text();
  return { status: r.status, ms: Date.now() - t0, text, json: JSON.parse(text), respSig: r.headers.get("x-agent-games-signature") };
}

const child = spawn("node", ["server.mjs"], {
  cwd: new URL(".", import.meta.url).pathname,
  env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, DATA_DIR: DATA },
  stdio: ["ignore", "pipe", "pipe"],
});
child.stderr.on("data", (d) => process.stderr.write("[server] " + d));
await new Promise((res) => {
  child.stdout.on("data", (d) => {
    if (String(d).includes("listening")) res();
  });
});

let failures = 0;
function check(label, cond, extra = "") {
  console.log((cond ? "PASS" : "FAIL") + "  " + label + (extra ? "  " + extra : ""));
  if (!cond) failures += 1;
}

try {
  const vk = JSON.parse(fs.readFileSync(new URL("./gatekeeper-vk.json", import.meta.url).pathname, "utf8"));

  // preflight
  const pf = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  check("preflight ok+shape", pf.status === 200 && pf.json.ok === true && pf.json.protocolVersion === "v1");
  check("preflight response signature valid", pf.respSig === sign(pf.text));

  // bad signature -> 401
  const bad = await post(task(), { badSig: true });
  check("bad signature rejected 401", bad.status === 401);

  const cases = [
    ["valid", task(), "APPROVE", "VALID_CONDITION", true],
    ["vk substitution", task({ proof_vk: OTHER_VK }), "REJECT", "VK_SUBSTITUTION", true],
    ["threshold", task({ public_balance: "999" }), "REJECT", "THRESHOLD_MISMATCH", true],
    ["expired", task({ current_block: 8430001 }), "REJECT", "EXPIRED_CONDITION", true],
    ["expired boundary cur==exp", task({ current_block: 8430000 }), "REJECT", "EXPIRED_CONDITION", true],
    ["recipient", task({ condition_recipient: ADDR2 }), "REJECT", "RECIPIENT_MISMATCH", true],
    ["amount overflow", task({ amount: "1001" }), "REJECT", "AMOUNT_OVERFLOW", true],
    ["boundary bal==min", task({ public_balance: "1000" }), "APPROVE", "VALID_CONDITION", true],
    ["boundary amt==max", task({ amount: "1000" }), "APPROVE", "VALID_CONDITION", true],
  ];
  for (const [label, t, dec, code, withProof] of cases) {
    const r = await post(t);
    let proofOk = null;
    if (r.json.proof) proofOk = await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof);
    check(
      label,
      r.status === 200 && r.json.decision === dec && r.json.reason_code === code && (!withProof || proofOk === true),
      `${r.json.decision}/${r.json.reason_code} proofOk=${proofOk} ${r.ms}ms`
    );
    check(label + " resp sig", r.respSig === sign(r.text));
  }

  // proof reuse: first use of a fresh proof_tx approves, second use (new task_id) rejects w/o proof
  const shared = "0xreuseddeadbeef";
  const first = await post(task({ proof_tx: shared }));
  const second = await post(task({ proof_tx: shared }));
  check("reuse first approves", first.json.decision === "APPROVE", `${first.json.decision}`);
  check(
    "reuse second rejects PROOF_REUSED no proof",
    second.json.decision === "REJECT" && second.json.reason_code === "PROOF_REUSED" && !second.json.proof
  );
  // idempotent replay of the SAME task_id returns the cached response
  const replay = await post(JSON.parse(JSON.stringify(task({ proof_tx: "0xreplay1" }))));
  const tSame = { ...replay, };
  const again = await post({ type: "agent-games.proof-gatekeeper.v1", task_id: `gk_test_${n}`, mode: "practice", input: task({ proof_tx: "0xreplay1" }).input });
  check("same task_id replay is cached", again.text === replay.text || again.json.decision === replay.json.decision);

  // timing: 10 fresh valid tasks end-to-end
  const times = [];
  for (let i = 0; i < 10; i++) {
    const r = await post(task());
    times.push(r.ms);
  }
  times.sort((a, b) => a - b);
  console.log(`TIMING valid-task e2e ms: median=${times[5]} worst=${times[times.length - 1]} all=${times.join(",")}`);
  check("worst e2e < 60s", times[times.length - 1] < 60000);
} finally {
  child.kill("SIGTERM");
}
console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
