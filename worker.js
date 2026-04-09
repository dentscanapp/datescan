// ============================================================
// DateScan – Lemon Squeezy Webhook Worker (Cloudflare)
// ============================================================
// Endpoints:
//   POST /webhook   ← Lemon Squeezy hits this on every event
//   GET  /check?user_id=XXX   ← Frontend polls this to learn Pro status
//
// Required Cloudflare bindings:
//   - KV Namespace binding named:  PRO_USERS
//   - Secret env var named:        LS_WEBHOOK_SECRET   (any random string,
//                                  must match what you put in LS dashboard)
// ============================================================

const VARIANT_TO_PLAN = {
  "1509528": "week",
  "1509643": "month",
  "1509836": "year",
};

const GRANT_EVENTS = new Set([
  "order_created",
  "subscription_created",
  "subscription_resumed",
  "subscription_unpaused",
  "subscription_payment_success",
  "subscription_payment_recovered",
]);

const REVOKE_EVENTS = new Set([
  "subscription_cancelled",
  "subscription_expired",
  "subscription_paused",
  "subscription_payment_failed",
  "order_refunded",
  "subscription_payment_refunded",
]);

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Signature",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    // ---- Webhook receiver ----
    if (url.pathname === "/webhook" && request.method === "POST") {
      const rawBody = await request.text();
      const signature = request.headers.get("X-Signature") || "";

      const valid = await verifyHmac(rawBody, signature, env.LS_WEBHOOK_SECRET);
      if (!valid) {
        return new Response("Invalid signature", { status: 401, headers: CORS });
      }

      let payload;
      try { payload = JSON.parse(rawBody); }
      catch { return new Response("Bad JSON", { status: 400, headers: CORS }); }

      const eventName = payload?.meta?.event_name || "";
      const userId = payload?.meta?.custom_data?.user_id;
      const attrs = payload?.data?.attributes || {};
      const variantId = String(
        attrs?.first_order_item?.variant_id ||
        attrs?.variant_id ||
        ""
      );
      const plan = VARIANT_TO_PLAN[variantId] || "unknown";

      if (!userId) {
        // No user_id passed → can't tie to a frontend session, just ack.
        return new Response("OK (no user_id)", { headers: CORS });
      }

      if (GRANT_EVENTS.has(eventName)) {
        await env.PRO_USERS.put(
          userId,
          JSON.stringify({ pro: true, plan, ts: Date.now(), event: eventName }),
        );
      } else if (REVOKE_EVENTS.has(eventName)) {
        await env.PRO_USERS.put(
          userId,
          JSON.stringify({ pro: false, plan, ts: Date.now(), event: eventName }),
        );
      }

      return new Response("OK", { headers: CORS });
    }

    // ---- Frontend status check ----
    if (url.pathname === "/check" && request.method === "GET") {
      const userId = url.searchParams.get("user_id") || "";
      if (!userId) {
        return json({ pro: false, reason: "no user_id" });
      }
      const raw = await env.PRO_USERS.get(userId);
      const data = raw ? JSON.parse(raw) : { pro: false };
      return json(data);
    }

    return new Response("Not found", { status: 404, headers: CORS });
  },
};

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

// HMAC-SHA256 verification (constant-time compare)
async function verifyHmac(body, signature, secret) {
  if (!secret || !signature) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  const expected = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}
