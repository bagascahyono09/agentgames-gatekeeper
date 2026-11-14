// Disk persistence: proof_tx seen-set + task_id -> response cache.
// Files live in DATA_DIR (default ./data). Writes are atomic (tmp + rename).
import fs from "node:fs";
import path from "node:path";

const dir = process.env.DATA_DIR || new URL("./data/", import.meta.url).pathname;
fs.mkdirSync(dir, { recursive: true });

const seenPath = path.join(dir, "seen-proof-tx.json");
const cachePath = path.join(dir, "response-cache.json");

function load(p, fallback) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return fallback;
  }
}
function save(p, obj) {
  const tmp = p + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, p);
}

const seen = new Set(load(seenPath, []));
const cache = new Map(Object.entries(load(cachePath, {})));

export function seenHas(proofTxLower) {
  return seen.has(proofTxLower);
}
export function seenAdd(proofTxLower) {
  if (proofTxLower && !seen.has(proofTxLower)) {
    seen.add(proofTxLower);
    save(seenPath, [...seen]);
  }
}
export function cacheGet(taskId) {
  return cache.get(taskId);
}
export function cacheSet(taskId, responseBodyString) {
  cache.set(taskId, responseBodyString);
  save(cachePath, Object.fromEntries(cache));
}
export function seenSize() {
  return seen.size;
}
