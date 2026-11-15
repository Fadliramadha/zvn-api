// Vercel serverless handler for the Zvn x402 paid API.
// Single catch-all: routes by req.url. No dependencies.
// payTo = user's Bitget wallet (connected wallet on vAPI).
// Price: 0.005 USDC per call (5000 base units, USDC 6 decimals).
const FACILITATOR = "https://x402.org/facilitator";
const PAY_TO = "0x3f573a438ee8b4fc52e9c65a4e2ddaa4dd75dc57";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const NETWORK = "eip155:8453";
const AMOUNT = "5000"; // 0.005 USDC

const offer = {
  x402Version: 2,
  error: "Payment required",
  resource: {
    url: "/paid",
    description: "Zvn paid API — a tiny paid endpoint.",
    mimeType: "application/json",
    serviceName: "Zvn API",
  },
  accepts: [
    {
      scheme: "exact",
      network: NETWORK,
      amount: AMOUNT,
      asset: USDC_BASE,
      payTo: PAY_TO,
      maxTimeoutSeconds: 120,
      extra: { name: "USD Coin", version: "2" },
    },
  ],
};

const openapi = {
  openapi: "3.0.3",
  info: { title: "Zvn API", version: "1.0.0", description: "A tiny paid API listed on vAPI Call." },
  paths: {
    "/paid": {
      post: {
        summary: "Paid endpoint — returns a small JSON payload after x402 payment.",
        "x-payment-info": offer.accepts[0],
        responses: {
          200: { description: "Paid response" },
          402: { description: "Payment required" },
        },
      },
    },
  },
};

function sendJson(res, status, obj, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.end(JSON.stringify(obj));
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Expose-Headers", "PAYMENT-REQUIRED, PAYMENT-RESPONSE");
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  const url = new URL(req.url, `https://${req.headers.host}`);
  const path = url.pathname;

  if (req.method === "GET" && path === "/") {
    return sendJson(res, 200, { service: "Zvn API", paidEndpoint: "POST /paid", price: "0.005 USDC" });
  }
  if (req.method === "GET" && path === "/openapi.json") {
    return sendJson(res, 200, openapi);
  }
  if (req.method === "GET" && path === "/.well-known/x402") {
    return sendJson(res, 200, { x402Version: 2, accepts: offer.accepts });
  }
  if (req.method === "POST" && path === "/paid") {
    const encoded = req.headers["payment-signature"];
    const paymentRequiredHeader = Buffer.from(JSON.stringify(offer)).toString("base64");
    if (!encoded) {
      return sendJson(res, 402, offer, { "PAYMENT-REQUIRED": paymentRequiredHeader });
    }
    let payment;
    try {
      payment = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
    } catch {
      return sendJson(res, 400, { error: "Invalid payment" });
    }
    const body = JSON.stringify({ x402Version: 2, paymentPayload: payment, paymentRequirements: offer.accepts[0] });
    const headers = { "content-type": "application/json" };
    try {
      const verify = await fetch(`${FACILITATOR}/verify`, { method: "POST", headers, body });
      const verified = await verify.json();
      if (!verify.ok || !verified.isValid) {
        return sendJson(res, 402, { error: "Payment verification failed" });
      }
      const settle = await fetch(`${FACILITATOR}/settle`, { method: "POST", headers, body });
      const settlement = await settle.json();
      if (!settle.ok || !settlement.success) {
        return sendJson(res, 502, { error: "Payment settlement failed" });
      }
      return sendJson(
        res,
        200,
        { resource: offer.resource, message: "Hello from Zvn API — payment received." },
        { "PAYMENT-RESPONSE": Buffer.from(JSON.stringify(settlement)).toString("base64") }
      );
    } catch (e) {
      return sendJson(res, 502, { error: "Facilitator unreachable", detail: String(e) });
    }
  }
  return sendJson(res, 404, { error: "Not found" });
}
