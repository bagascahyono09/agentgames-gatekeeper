// Groth16 proving for the gatekeeper circuit + field encodings.
// Circuit inputs (13, all size 1; order of public signals verified by probing):
//   [output commitment] registeredVkHash, proofVkHash, minimum, publicBalance,
//   expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//   maxTransfer, decision, taskId   (+ private: salt)
import * as snarkjs from "snarkjs";
import sha3 from "js-sha3";
const { keccak_256 } = sha3;
import { randomBytes } from "node:crypto";
import fs from "node:fs";

export const BN128_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const WASM = new URL("../circuits/gatekeeper.wasm", import.meta.url).pathname;
const ZKEY = new URL("../circuits/gatekeeper_final.zkey", import.meta.url).pathname;

let vkCache = null;
export async function loadVk() {
  if (!vkCache) {
    // Exported once from gatekeeper_final.zkey via the snarkjs CLI (2026-11-15).
    const p = new URL("./gatekeeper-vk.json", import.meta.url).pathname;
    vkCache = JSON.parse(fs.readFileSync(p, "utf8"));
  }
  return vkCache;
}

// A 0x-hex hash/address or decimal string -> field element (mod p).
export function fieldFromHexOrDec(v) {
  const s = String(v).trim();
  const n = s.startsWith("0x") || s.startsWith("0X") ? BigInt(s) : BigInt(s);
  return ((n % BN128_P) + BN128_P) % BN128_P;
}

// task_id -> field element: digits pass through; otherwise keccak256(utf8) mod p.
export function fieldFromTaskId(taskId) {
  const s = String(taskId);
  if (/^[0-9]+$/.test(s)) return BigInt(s) % BN128_P;
  return BigInt("0x" + keccak_256(s)) % BN128_P;
}

export function randomSalt() {
  return BigInt("0x" + randomBytes(31).toString("hex")) % BN128_P;
}

export function buildCircuitInput(task, decision /* "APPROVE"|"REJECT" */) {
  const i = task.input;
  return {
    decision: decision === "APPROVE" ? 1 : 0,
    publicBalance: BigInt(i.public_balance).toString(),
    minimum: BigInt(i.minimum).toString(),
    recipient: fieldFromHexOrDec(i.recipient).toString(),
    conditionRecipient: fieldFromHexOrDec(i.condition_recipient).toString(),
    amount: BigInt(i.amount).toString(),
    maxTransfer: BigInt(i.max_transfer).toString(),
    expiryBlock: BigInt(i.expiry_block).toString(),
    currentBlock: BigInt(i.current_block).toString(),
    registeredVkHash: fieldFromHexOrDec(i.registered_vk).toString(),
    proofVkHash: fieldFromHexOrDec(i.proof_vk).toString(),
    salt: randomSalt().toString(),
    taskId: fieldFromTaskId(task.task_id).toString(),
  };
}

export async function prove(input) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, publicSignals };
}

export async function selfVerify(proof, publicSignals) {
  const vk = await loadVk();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}
