// Optional Kurier submission (audit trail). Non-blocking: the response to the
// platform never waits on Kurier. If KURIER_API_KEY is unset this is a no-op.
const API = "https://api.kurier.xyz/api/v1";
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export function kurierEnabled() {
  return !!process.env.KURIER_API_KEY;
}

export async function submitProof(proof, publicSignals, log) {
  const key = process.env.KURIER_API_KEY;
  if (!key) return;
  try {
    const r = await fetch(`${API}/submit-proof/${key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: VK_HASH },
      }),
    });
    const job = await r.json();
    log({ kurier_submit: job });
    if (!job.jobId) return;
    const deadline = Date.now() + 240_000;
    while (Date.now() < deadline) {
      await new Promise((res) => setTimeout(res, 5000));
      const s = await fetch(`${API}/job-status/${key}/${job.jobId}`);
      const st = await s.json();
      if (["Finalized", "Failed"].includes(st.status)) {
        log({ kurier_final: { jobId: job.jobId, status: st.status, txHash: st.txHash ?? null } });
        return;
      }
    }
    log({ kurier_final: { jobId: job.jobId, status: "timeout-still-pending" } });
  } catch (e) {
    log({ kurier_error: String(e).slice(0, 200) });
  }
}
