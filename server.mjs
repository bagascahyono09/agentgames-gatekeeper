// Proof Gatekeeper agent — public HTTPS endpoint (behind cloudflared tunnel).
// Protocol: POST /agent with x-agent-games-signature = HMAC(secret, raw body).
//   - preflight: {"type":"agent-games.preflight.v1"} -> {ok:true, protocolVersion:"v1"}
//   - task:      {"type":"agent-games.proof-gatekeeper.v1", task_id, mode, input:{...}}
//                -> signed {decision, reason_code, proof_tx, proof, public_signals}
// Fail closed: any error on the decision path still returns a signed REJECT
// carrying the engine's reason when known; proving failures degrade to a
// proof-less decision (decision points preserved, proof bonus lost).
import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { decide } from "./engine.mjs";
import { buildCircuitInput, prove, selfVerify, loadVk } from "./prover.mjs";
import { seenHas, seenAdd, cacheGet, cacheSet, seenSize } from "./store.mjs";
import { submitProof, kurierEnabled } from "./kurier.mjs";

const PORT = Number(process.env.PORT || 8790);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const OUT_FORMAT = (process.env.HMAC_OUT_FORMAT || "hex").toLowerCase(); // hex|base64
const DATA_DIR = process.env.DATA_DIR || new URL("./data/", import.meta.url).pathname;
const LOG = path.join(DATA_DIR, "tasks.log");
fs.mkdirSync(DATA_DIR, { recursive: true });

if (!SECRET) {
  console.error("AGENT_GAMES_HMAC_SECRET is not set — refusing to start");
  process.exit(1);
}

function log(obj) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...obj }) + "\n";
  fs.appendFile(LOG, line, () => {});
  console.log(line.trim());
}

function hmacHex(raw) {
  return createHmac("sha256", SECRET).update(raw).digest("hex");
}
function hmacB64(raw) {
  return createHmac("sha256", SECRET).update(raw).digest("base64");
}
function sign(raw) {
  return OUT_FORMAT === "base64" ? hmacB64(raw) : hmacHex(raw);
}
function verifyInbound(raw, header) {
  if (!header) return false;
  const given = String(header).trim();
  const candidates = [hmacHex(raw), hmacHex(raw).toUpperCase(), hmacB64(raw), "sha256=" + hmacHex(raw)];
  return candidates.some((c) => {
    if (c.length !== given.length) return false;
    try {
      return timingSafeEqual(Buffer.from(c), Buffer.from(given));
    } catch {
      return false;
    }
  });
}

function sendSigned(res, status, bodyObj) {
  const body = typeof bodyObj === "string" ? bodyObj : JSON.stringify(bodyObj);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": sign(body),
  });
  res.end(body);
  return body;
}

async function handleTask(task, t0) {
  const taskId = String(task.task_id ?? "");
  const cached = cacheGet(taskId);
  if (cached) {
    log({ event: "task_replay", task_id: taskId, ms: Date.now() - t0 });
    return cached;
  }
  const input = task.input || {};
  const proofTxNorm = String(input.proof_tx ?? "").trim().toLowerCase();
  let verdict;
  try {
    verdict = decide(input, seenHas);
  } catch (e) {
    // Malformed fields: fail closed.
    verdict = { decision: "REJECT", reason_code: "INVALID_PAYLOAD", needsProof: false };
    log({ event: "engine_error", task_id: taskId, error: String(e).slice(0, 200) });
  }
  const resp = { decision: verdict.decision, reason_code: verdict.reason_code, proof_tx: input.proof_tx ?? null };
  let proofMs = null;
  if (verdict.needsProof) {
    const p0 = Date.now();
    try {
      const circuitInput = buildCircuitInput(task, verdict.decision);
      const { proof, publicSignals } = await prove(circuitInput);
      proofMs = Date.now() - p0;
      const okSelf = await selfVerify(proof, publicSignals).catch(() => false);
      if (okSelf) {
        resp.proof = proof;
        resp.public_signals = publicSignals;
        // Audit-trail submission; never blocks the response.
        submitProof(proof, publicSignals, (o) => log({ task_id: taskId, ...o }));
      } else {
        log({ event: "self_verify_failed", task_id: taskId });
      }
    } catch (e) {
      proofMs = Date.now() - p0;
      log({ event: "prove_error", task_id: taskId, error: String(e).slice(0, 300) });
    }
  }
  // Record the proof ref as seen only after this task's own reuse check.
  seenAdd(proofTxNorm);
  const body = JSON.stringify(resp);
  cacheSet(taskId, body);
  log({
    event: "task",
    task_id: taskId,
    mode: task.mode ?? null,
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof: !!resp.proof,
    proof_ms: proofMs,
    total_ms: Date.now() - t0,
    input,
  });
  return body;
}

const server = http.createServer((req, res) => {
  const t0 = Date.now();
  if (req.method === "GET" && (req.url === "/healthz" || req.url === "/health")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, seen: seenSize(), kurier: kurierEnabled() }));
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "not found" }));
    return;
  }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    const sig = req.headers["x-agent-games-signature"];
    if (!verifyInbound(raw, sig)) {
      log({ event: "bad_signature", ms: Date.now() - t0 });
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "invalid signature" }));
      return;
    }
    let msg;
    try {
      msg = JSON.parse(raw.toString("utf8"));
    } catch {
      sendSigned(res, 400, { ok: false, error: "invalid json" });
      return;
    }
    try {
      if (msg.type === "agent-games.preflight.v1") {
        const body = sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
        log({ event: "preflight", ms: Date.now() - t0, body });
        return;
      }
      if (msg.type === "agent-games.proof-gatekeeper.v1") {
        const body = await handleTask(msg, t0);
        res.writeHead(200, {
          "content-type": "application/json",
          "x-agent-games-signature": sign(body),
        });
        res.end(body);
        return;
      }
      sendSigned(res, 400, { ok: false, error: "unknown type" });
    } catch (e) {
      log({ event: "handler_error", error: String(e).slice(0, 300) });
      try {
        sendSigned(res, 200, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: msg?.input?.proof_tx ?? null });
      } catch {}
    }
  });
});

await loadVk(); // warm the VK cache so the first task pays no export cost
server.listen(PORT, "127.0.0.1", () => {
  log({ event: "listening", port: PORT, out_format: OUT_FORMAT, kurier: kurierEnabled() });
});
