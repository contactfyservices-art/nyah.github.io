// GET  /api/posts        -> liste publique des articles publiés
// POST /api/posts         -> crée un article (nécessite un jeton admin valide)
// DELETE /api/posts?id=.. -> supprime un article (nécessite un jeton admin valide)

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function isValidToken(env, token) {
  if (!token) return false;
  const parts = token.split(":");
  if (parts.length !== 3) return false;
  const [prefix, expiresStr, sig] = parts;
  if (prefix !== "admin") return false;
  const expires = parseInt(expiresStr, 10);
  if (!expires || Date.now() > expires) return false;
  const expectedSig = await hmac(env.ADMIN_SECRET || "fallback-secret-change-me", `admin:${expiresStr}`);
  return expectedSig === sig;
}

const INDEX_KEY = "posts:index";

export async function onRequestGet(context) {
  const { env } = context;
  const indexRaw = await env.SITE_KV.get(INDEX_KEY);
  const ids = indexRaw ? JSON.parse(indexRaw) : [];
  const posts = [];
  for (const id of ids) {
    const raw = await env.SITE_KV.get(`post:${id}`);
    if (raw) posts.push(JSON.parse(raw));
  }
  posts.sort((a, b) => b.createdAt - a.createdAt);
  return new Response(JSON.stringify({ posts }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const token = request.headers.get("Authorization") || "";
  if (!(await isValidToken(env, token.replace("Bearer ", "")))) {
    return new Response(JSON.stringify({ error: "Non autorisé" }), { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: "Requête invalide" }), { status: 400 });
  }

  const title = (body.title || "").toString().slice(0, 200);
  const html = (body.html || "").toString().slice(0, 50000);
  const photo = (body.photo || "").toString().slice(0, 8_000_000); // data URI, ~6MB max décodé

  if (!title.trim() && !html.trim() && !photo) {
    return new Response(JSON.stringify({ error: "Article vide" }), { status: 400 });
  }

  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const post = { id, title, html, photo, createdAt: Date.now() };

  await env.SITE_KV.put(`post:${id}`, JSON.stringify(post));

  const indexRaw = await env.SITE_KV.get(INDEX_KEY);
  const ids = indexRaw ? JSON.parse(indexRaw) : [];
  ids.push(id);
  await env.SITE_KV.put(INDEX_KEY, JSON.stringify(ids));

  return new Response(JSON.stringify({ ok: true, post }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  const token = request.headers.get("Authorization") || "";
  if (!(await isValidToken(env, token.replace("Bearer ", "")))) {
    return new Response(JSON.stringify({ error: "Non autorisé" }), { status: 401 });
  }

  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return new Response(JSON.stringify({ error: "id manquant" }), { status: 400 });

  await env.SITE_KV.delete(`post:${id}`);
  const indexRaw = await env.SITE_KV.get(INDEX_KEY);
  const ids = indexRaw ? JSON.parse(indexRaw) : [];
  const newIds = ids.filter((x) => x !== id);
  await env.SITE_KV.put(INDEX_KEY, JSON.stringify(newIds));

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
