import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;
const AUTH_SECRET = process.env.AUTH_SECRET || "";
const SITE_DOMAIN = process.env.SITE_DOMAIN || "exuberant.pw";
const SITE_NAME = process.env.SITE_NAME || "Exuberant";

if (!REDIS_URL || !REDIS_TOKEN) throw new Error("Missing Upstash env");
if (!RESEND_KEY) throw new Error("Missing Resend env");
if (AUTH_SECRET.length < 16) throw new Error("AUTH_SECRET too short");

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

function setSid(res, sid) {
  res.setHeader(
    "Set-Cookie",
    `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${60 * 60 * 24 * 30}`
  );
}

function clearSid(res) {
  res.setHeader(
    "Set-Cookie",
    `sid=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`
  );
}

async function requireAuth(req, res) {
  const sid = getSid(req);
  if (!sid) { j(res, 401, { ok: false, error: "NO_SESSION" }); return null; }
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { j(res, 401, { ok: false, error: "NO_SESSION" }); return null; }
  return se.result; // email
}

function ipOf(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  return (xf.split(",")[0] || "").trim() || req.socket?.remoteAddress || "unknown";
}

async function rateLimit(req, bucket, limit, windowSec) {
  const key = `rl:${ipOf(req)}:${bucket}`;
  const cur = await redis("incr", key);
  if (cur.result === 1) await redis("expire", key, String(windowSec));
  return cur.result <= limit;
}

function normEmail(e) {
  return String(e || "").trim().toLowerCase();
}
function normUser(u) {
  u = String(u || "").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

function okPassword(p) { return String(p || "").length >= 8 && String(p || "").length <= 72; }
function okName(n) { n = String(n || "").trim(); return n.length >= 1 && n.length <= 40; }
function okUsername(u) { return /^[a-z0-9_]{3,20}$/.test(u) && !u.includes("__"); }

function pwHash(password) {
  // simple HMAC-based hash (stable). Do not change AUTH_SECRET after launch.
  return crypto.createHmac("sha256", AUTH_SECRET).update(String(password || "")).digest("hex");
}

function genCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendCodeEmail(to, code) {
  const from = `Exuberant <auth@${SITE_DOMAIN}>`;
  const subject = `Код входа ${SITE_NAME}`;
  const html = `<div style="font-family:Arial,sans-serif">
    <div style="font-size:14px;opacity:.7">${SITE_NAME}</div>
    <div style="font-size:28px;font-weight:800;letter-spacing:2px;margin:10px 0">${code}</div>
    <div style="font-size:13px;opacity:.75">Код действует 5 минут.</div>
  </div>`;

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ from, to, subject, html })
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`Resend ${r.status}: ${t}`);
  }
}

export default async function handler(req, res) {
  const action = String(req.query.action || "");
  const body = await readBody(req);

  // global RL
  if (!(await rateLimit(req, "auth", 90, 60))) return j(res, 429, { ok: false, error: "RATE_LIMIT" });

  // REGISTER: send code
  if (action === "register_send") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });

    const email = normEmail(body.email);
    const password = String(body.password || "");

    if (!email.includes("@")) return j(res, 400, { ok: false, error: "BAD_EMAIL" });
    if (!okPassword(password)) return j(res, 400, { ok: false, error: "BAD_PASSWORD" });

    const exists = await redis("get", `user:email:${email}`);
    if (exists.result) return j(res, 200, { ok: false, error: "ACCOUNT_EXISTS" });

    const code = genCode();
    await redis(
      "set",
      `pending:${email}`,
      JSON.stringify({ code, pw: pwHash(password), createdAt: Date.now() }),
      "EX",
      300
    );
    await sendCodeEmail(email, code);
    return j(res, 200, { ok: true });
  }

  // REGISTER: verify code
  if (action === "register_verify") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });

    const email = normEmail(body.email);
    const code = String(body.code || "").trim();

    const p = await redis("get", `pending:${email}`);
    if (!p.result) return j(res, 200, { ok: false, error: "NO_PENDING" });

    const data = JSON.parse(p.result);
    if (data.code !== code) return j(res, 200, { ok: false, error: "INVALID_CODE" });

    data.verified = true;
    await redis("set", `pending:${email}`, JSON.stringify(data), "EX", 600);
    return j(res, 200, { ok: true });
  }

  // REGISTER: setup profile
  if (action === "register_setup") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });

    const email = normEmail(body.email);
    const name = String(body.name || "").trim();
    const username = normUser(body.username);

    if (!okName(name)) return j(res, 200, { ok: false, error: "BAD_NAME" });
    if (!okUsername(username)) return j(res, 200, { ok: false, error: "BAD_USERNAME" });

    const p = await redis("get", `pending:${email}`);
    if (!p.result) return j(res, 200, { ok: false, error: "NO_PENDING" });

    const data = JSON.parse(p.result);
    if (!data.verified) return j(res, 200, { ok: false, error: "NO_PENDING" });

    const taken = await redis("get", `user:username:${username}`);
    if (taken.result) return j(res, 200, { ok: false, error: "USERNAME_TAKEN" });

    const user = {
      email,
      username,
      name,
      about: "",
      avatar: "",
      badges: [],
      pw: data.pw,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    await redis("set", `user:email:${email}`, JSON.stringify(user));
    await redis("set", `user:username:${username}`, email);
    await redis("del", `pending:${email}`);

    const sid = crypto.randomBytes(24).toString("hex");
    await redis("set", `sess:${sid}`, email, "EX", String(60 * 60 * 24 * 30));
    setSid(res, sid);

    return j(res, 200, { ok: true });
  }

  // LOGIN
  if (action === "login") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });
    if (!(await rateLimit(req, "login", 25, 60))) return j(res, 429, { ok: false, error: "RATE_LIMIT" });

    const email = normEmail(body.email);
    const password = String(body.password || "");

    if (!email.includes("@")) return j(res, 200, { ok: false, error: "BAD_EMAIL" });

    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return j(res, 200, { ok: false, error: "NO_ACCOUNT" });

    const user = JSON.parse(u.result);
    if (user.pw !== pwHash(password)) return j(res, 200, { ok: false, error: "BAD_CREDENTIALS" });

    const sid = crypto.randomBytes(24).toString("hex");
    await redis("set", `sess:${sid}`, email, "EX", String(60 * 60 * 24 * 30));
    setSid(res, sid);

    return j(res, 200, { ok: true });
  }

  // LOGOUT
  if (action === "logout") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });
    clearSid(res);
    return j(res, 200, { ok: true });
  }

  // PROFILE GET
  if (action === "profile_get") {
    const email = await requireAuth(req, res);
    if (!email) return;
    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return j(res, 200, { ok: false, error: "NO_ACCOUNT" });
    const user = JSON.parse(u.result);
    return j(res, 200, { ok: true, user: {
      email: user.email,
      username: user.username,
      name: user.name,
      about: user.about || "",
      avatar: user.avatar || "",
      badges: user.badges || []
    }});
  }

  // PROFILE SET
  if (action === "profile_set") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });
    const email = await requireAuth(req, res);
    if (!email) return;

    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return j(res, 200, { ok: false, error: "NO_ACCOUNT" });

    const user = JSON.parse(u.result);

    const newName = body.name !== undefined ? String(body.name).trim() : user.name;
    const newAbout = body.about !== undefined ? String(body.about) : (user.about || "");
    const newBadges = Array.isArray(body.badges) ? body.badges.map(String) : (user.badges || []);
    const newUsername = body.username !== undefined ? normUser(body.username) : user.username;

    if (!okName(newName)) return j(res, 200, { ok: false, error: "BAD_NAME" });
    if (!okUsername(newUsername)) return j(res, 200, { ok: false, error: "BAD_USERNAME" });
    if (newAbout.length > 240) return j(res, 200, { ok: false, error: "BAD_ABOUT" });

    if (newUsername !== user.username) {
      const taken = await redis("get", `user:username:${newUsername}`);
      if (taken.result) return j(res, 200, { ok: false, error: "USERNAME_TAKEN" });
      await redis("del", `user:username:${user.username}`);
      await redis("set", `user:username:${newUsername}`, email);
    }

    const allowed = new Set(["premium","verified","early"]);
    const filtered = [];
    for (const b of newBadges) {
      if (allowed.has(b) && !filtered.includes(b)) filtered.push(b);
      if (filtered.length >= 5) break;
    }

    user.name = newName;
    user.about = newAbout;
    user.username = newUsername;
    user.badges = filtered;
    user.updatedAt = Date.now();

    await redis("set", `user:email:${email}`, JSON.stringify(user));
    return j(res, 200, { ok: true });
  }

  // AVATAR SET (dataUrl)
  if (action === "avatar_set") {
    if (req.method !== "POST") return j(res, 405, { ok: false, error: "METHOD" });
    const email = await requireAuth(req, res);
    if (!email) return;

    const dataUrl = String(body.dataUrl || "");
    if (!dataUrl.startsWith("data:image/")) return j(res, 200, { ok: false, error: "BAD_IMAGE" });
    if (dataUrl.length > 2_000_000) return j(res, 200, { ok: false, error: "TOO_LARGE" });

    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return j(res, 200, { ok: false, error: "NO_ACCOUNT" });

    const user = JSON.parse(u.result);
    user.avatar = dataUrl;
    user.updatedAt = Date.now();
    await redis("set", `user:email:${email}`, JSON.stringify(user));
    return j(res, 200, { ok: true });
  }

  return j(res, 404, { ok: false, error: "UNKNOWN_ACTION" });
}
