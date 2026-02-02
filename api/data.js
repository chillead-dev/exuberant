import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

if (!REDIS_URL || !REDIS_TOKEN) throw new Error("Missing Upstash env");

function j(res, code, obj) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.end(JSON.stringify(obj));
}

async function redis(cmd, ...args) {
  const url = `${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${REDIS_TOKEN}` } });
  const out = await r.json();
  if (out.error) throw new Error(out.error);
  return out;
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

function getSid(req) {
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}
async function requireAuth(req, res) {
  const sid = getSid(req);
  if (!sid) { j(res, 401, { ok: false, error: "NO_SESSION" }); return null; }
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { j(res, 401, { ok: false, error: "NO_SESSION" }); return null; }
  return se.result;
}

function normUser(u) {
  u = String(u || "").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

function snippetFrom(text) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  return t.slice(0, 180);
}

export default async function handler(req, res) {
  const action = String(req.query.action || "");
  const body = await readBody(req);

  const email = await requireAuth(req, res);
  if (!email) return;

  // CREATE POST
  if (action === "post_create") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });

    const title = String(body.title || "").trim();
    const text = String(body.body || "").trim();

    if (title.length < 3) return j(res, 200, { ok: false, error: "BAD_TITLE" });
    if (text.length < 10) return j(res, 200, { ok: false, error: "BAD_BODY" });
    if (text.length > 20000) return j(res, 200, { ok: false, error: "TOO_LARGE" });

    const meRaw = (await redis("get", `user:email:${email}`)).result;
    if (!meRaw) return j(res, 200, { ok: false, error: "NO_PROFILE" });
    const me = JSON.parse(meRaw);

    const id = crypto.randomBytes(8).toString("hex");
    const post = {
      id,
      title: title.slice(0, 140),
      body: text,
      snippet: snippetFrom(text),
      username: me.username,
      avatar: me.avatar || "",
      badges: me.badges || [],
      createdAt: Date.now()
    };

    await redis("set", `post:${id}`, JSON.stringify(post));
    await redis("lpush", "posts", id);
    await redis("ltrim", "posts", "0", "300");

    return j(res, 200, { ok: true, id });
  }

  // GET POSTS
  if (action === "posts_get") {
    const author = normUser(req.query.author || "");
    const ids = (await redis("lrange", "posts", "0", "40")).result || [];

    const out = [];
    for (const id of ids) {
      const p = await redis("get", `post:${id}`);
      if (!p.result) continue;
      const post = JSON.parse(p.result);
      if (author && String(post.username || "").toLowerCase() !== author) continue;
      out.push(post);
    }
    return j(res, 200, { ok: true, posts: out });
  }

  // GET ONE POST
  if (action === "post_get") {
    const id = String(req.query.id || "");
    if (!id) return j(res, 200, { ok: false, error: "BAD_ID" });
    const p = await redis("get", `post:${id}`);
    if (!p.result) return j(res, 200, { ok: false, error: "NOT_FOUND" });
    return j(res, 200, { ok: true, post: JSON.parse(p.result) });
  }

  // SEARCH USERS
  if (action === "users_search") {
    const q = normUser(req.query.q || "");
    if (q.length < 2) return j(res, 200, { ok: true, users: [] });

    // IMPORTANT: KEYS is ok for small project; later we optimize to SCAN/Index.
    const keys = (await redis("keys", "user:username:*")).result || [];
    const users = [];

    for (const k of keys) {
      const uname = String(k).slice("user:username:".length);
      if (!uname.includes(q)) continue;

      const em = (await redis("get", k)).result;
      if (!em) continue;
      const u = await redis("get", `user:email:${em}`);
      if (!u.result) continue;
      const user = JSON.parse(u.result);

      users.push({
        username: user.username,
        name: user.name || "",
        avatar: user.avatar || "",
        badges: user.badges || []
      });

      if (users.length >= 20) break;
    }

    return j(res, 200, { ok: true, users });
  }

  // PUBLIC USER PROFILE
  if (action === "user_get") {
    const u = normUser(req.query.u || "");
    if (!u) return j(res, 200, { ok: false, error: "BAD_USER" });

    const em = (await redis("get", `user:username:${u}`)).result;
    if (!em) return j(res, 200, { ok: false, error: "NOT_FOUND" });

    const raw = (await redis("get", `user:email:${em}`)).result;
    if (!raw) return j(res, 200, { ok: false, error: "NOT_FOUND" });

    const user = JSON.parse(raw);
    return j(res, 200, {
      ok: true,
      user: {
        username: user.username,
        name: user.name || "",
        about: user.about || "",
        avatar: user.avatar || "",
        badges: user.badges || []
      }
    });
  }

  return j(res, 404, { ok: false, error: "UNKNOWN_ACTION" });
}
