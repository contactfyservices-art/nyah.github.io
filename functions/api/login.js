// POST /api/login  { code: "..." }
// Vérifie le code admin côté serveur (jamais exposé au client) et renvoie un jeton signé.

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: "Requête invalide" }), { status: 400 });
  }

  const code = (body && body.code || "").toString();
  if (!env.ADMIN_CODE || code !== env.ADMIN_CODE) {
    return new Response(JSON.stringify({ error: "Code incorrect" }), { status: 401 });
  }

  const expires = Date.now() + 1000 * 60 * 60 * 12; // 12 heures
  const payload = `admin:${expires}`;
  const sig = await hmac(env.ADMIN_SECRET || "fallback-secret-change-me", payload);
  const token = `${payload}:${sig}`;

  return new Response(JSON.stringify({ token }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
