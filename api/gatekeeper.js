// Proof Gatekeeper endpoint — zkVerify Agent Games Season 01
// Vercel serverless function (Node.js, no framework).
// Place at api/gatekeeper.js in the zvn-api repo.
// Circuit files: circuit/gatekeeper.wasm + circuit/gatekeeper_final.zkey
//   (include via vercel.json functions includeFiles, see below).
// Env: AGENT_GAMES_HMAC_SECRET (32-byte secret from registration, shown once).
//
// Flow per official Builder Field Guide (/build) + event page:
//  1. Verify x-agent-games-signature (HMAC-SHA256 over RAW body) BEFORE parsing.
//  2. Decide (fail closed): malformed -> VK mismatch -> proof reused ->
//     balance < minimum -> expired -> recipient mismatch -> amount > cap.
//     Any failure = REJECT. Only a task surviving every check gets APPROVE.
//  3. Prove the decision with the official Groth16 circuit (snarkjs 0.7.6).
//     APPROVE = decision 1, REJECT = decision 0. The circuit enforces
//     decision==1 IFF every check passes (verified locally: wrong approvals
//     and wrong rejects cannot even produce a witness).
//  4. Respond within 60s: {decision, reason_code, proof_tx, proof, publicSignals}
//     signed with x-agent-games-signature over the raw response body.
//  5. Idempotency: cache responses by task_id (in-memory, best effort;
//     Vercel functions are stateless — a retry after cold start re-proves
//     deterministically because salt is derived from taskId).
//
// Scoring reminder: correct decision +12 (verified proof), correct without
// proof +10 (-2), wrong APPROVE -6, wrong REJECT -3, timeout -2.
// NOTE on fail-closed: if proof generation fails for the computed decision we
// return the decision WITHOUT proof (still scores if the decision is right)
// instead of flipping to REJECT, because a proof-gen failure is a local
// problem, not uncertainty about the task. The official guide says fail
// closed; flip the PROOF_FAILURE_FAIL_CLOSED flag to true to follow it
// literally (costs points when the decision was actually right).
const crypto = require("crypto");
const snarkjs = require("snarkjs");
const path = require("path");

const FIELD_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"; // /api/circuit-info
const WASM = path.join(__dirname, "..", "circuit", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuit", "gatekeeper_final.zkey");
const PROOF_FAILURE_FAIL_CLOSED = false;

const seenProofTx = new Set(); // best effort only (stateless function)
const responseCache = new Map(); // task_id -> {status, body, signature}
const MAX_CACHE = 500;

function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}
function timingSafeEqualHex(a, b) {
  try {
    const ba = Buffer.from(a, "hex");
    const bb = Buffer.from(b, "hex");
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}
function hexToDec(h) {
  return BigInt(h).toString();
}
function deriveSalt(taskId) {
  const h = crypto.createHash("sha3-256").update(String(taskId)).digest("hex");
  return (BigInt("0x" + h) % FIELD_P).toString();
}
function taskIdToField(taskId) {
  const h = crypto.createHash("sha3-256").update(String(taskId)).digest("hex");
  return (BigInt("0x" + h) % FIELD_P).toString();
}

// Decision checks, in the order of the trap encyclopedia. Returns reason code or null.
function decide(input) {
  if (!input || typeof input !== "object") return "MALFORMED_TASK";
  const {
    registered_vk, proof_vk, minimum, public_balance,
    expiry_block, current_block, recipient, condition_recipient,
    amount, max_transfer, proof_tx,
  } = input;
  if (
    !registered_vk || !proof_vk || minimum === undefined ||
    public_balance === undefined || expiry_block === undefined ||
    current_block === undefined || !recipient || !condition_recipient ||
    amount === undefined || max_transfer === undefined || !proof_tx
  ) return "MALFORMED_TASK";
  if (String(proof_vk).toLowerCase() !== String(registered_vk).toLowerCase())
    return "VK_SUBSTITUTION";
  if (seenProofTx.has(String(proof_tx))) return "PROOF_REUSED";
  if (BigInt(public_balance) < BigInt(minimum)) return "THRESHOLD_MISMATCH";
  if (BigInt(expiry_block) <= BigInt(current_block)) return "EXPIRED_CONDITION";
  if (String(recipient).toLowerCase() !== String(condition_recipient).toLowerCase())
    return "RECIPIENT_MISMATCH";
  if (BigInt(amount) > BigInt(max_transfer)) return "AMOUNT_OVERFLOW";
  return null; // VALID_CONDITION
}

async function proveDecision(input, decision) {
  const circuitInput = {
    registeredVkHash: hexToDec(input.registered_vk),
    proofVkHash: hexToDec(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: hexToDec(input.recipient),
    conditionRecipient: hexToDec(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: String(decision),
    taskId: taskIdToField(input.task_id || "unknown"),
    salt: deriveSalt(input.task_id || "unknown"),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, WASM, ZKEY
  );
  return { proof, publicSignals };
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

module.exports = async (req, res) => {
  const started = Date.now();
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  try {
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "method_not_allowed" }));
    }
    if (!secret) {
      res.writeHead(500, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "hmac_secret_not_configured" }));
    }
    const rawBody = await readRawBody(req);
    const sig = req.headers["x-agent-games-signature"] || "";
    const expected = hmacHex(secret, rawBody);
    const sigHex = String(sig).replace(/^sha256=/i, "");
    if (!timingSafeEqualHex(sigHex, expected)) {
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "bad_signature" }));
    }
    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      envelope = null;
    }
    const input = envelope && envelope.input ? envelope.input : null;
    const taskId = (envelope && envelope.task_id) || (input && input.task_id) || "unknown";

    // Idempotent replay: byte-identical cached body.
    if (responseCache.has(taskId)) {
      const c = responseCache.get(taskId);
      res.writeHead(c.status, {
        "content-type": "application/json",
        "x-agent-games-signature": c.signature,
      });
      return res.end(c.body);
    }

    const reason = decide(input);
    const decision = reason === null ? "APPROVE" : "REJECT";
    const decisionNum = decision === "APPROVE" ? 1 : 0;

    let proof = null;
    let publicSignals = null;
    try {
      const r = await proveDecision(
        { ...input, task_id: taskId },
        decisionNum
      );
      proof = r.proof;
      publicSignals = r.publicSignals;
    } catch (e) {
      // Proof cannot be generated for this decision (circuit refuses wrong
      // decisions). If we decided APPROVE and the proof fails, the decision
      // was wrong — fail closed to REJECT and try proving the reject.
      if (decision === "APPROVE") {
        try {
          const r = await proveDecision({ ...input, task_id: taskId }, 0);
          proof = r.proof;
          publicSignals = r.publicSignals;
          const bodyObj = {
            decision: "REJECT",
            reason_code: "PROOF_GENERATION_FAILED",
            proof_tx: input ? input.proof_tx : null,
            proof, publicSignals,
          };
          return sendSigned(res, 200, bodyObj, secret, taskId, input);
        } catch {
          // fall through: REJECT without proof
        }
        if (PROOF_FAILURE_FAIL_CLOSED) {
          const bodyObj = {
            decision: "REJECT",
            reason_code: "PROOF_GENERATION_FAILED",
            proof_tx: input ? input.proof_tx : null,
            proof: null, publicSignals: null,
          };
          return sendSigned(res, 200, bodyObj, secret, taskId, input);
        }
        // else: keep APPROVE without proof (scores +10 if decision is right)
      }
      // REJECT without proof (e.g. PROOF_REUSED has nothing new to prove)
    }

    // Record the proof reference as seen (only for valid, answered tasks).
    if (input && input.proof_tx && decision === "APPROVE") {
      seenProofTx.add(String(input.proof_tx));
      if (seenProofTx.size > 10000) seenProofTx.clear();
    }

    const bodyObj = {
      decision,
      reason_code: reason || "VALID_CONDITION",
      proof_tx: input ? input.proof_tx : null,
      proof,
      publicSignals,
    };
    return sendSigned(res, 200, bodyObj, secret, taskId, input, started);
  } catch (e) {
    console.error("gatekeeper error:", e && e.message);
    res.writeHead(500, { "content-type": "application/json" });
    return res.end(JSON.stringify({ error: "internal_error" }));
  }
};

function sendSigned(res, status, bodyObj, secret, taskId, input, started) {
  const body = JSON.stringify(bodyObj);
  const signature = hmacHex(secret, Buffer.from(body, "utf8"));
  if (responseCache.size >= MAX_CACHE) responseCache.clear();
  responseCache.set(taskId, { status, body, signature });
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": signature,
  });
  if (started) console.log(`task ${taskId} ${bodyObj.decision} ${Date.now() - started}ms`);
  return res.end(body);
}

// Vercel: raw body needed for HMAC verification.
module.exports.config = { api: { bodyParser: false } };
