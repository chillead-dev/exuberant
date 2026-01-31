import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;

const SITE_NAME = process.env.SITE_NAME || "exuberant";
const SITE_DOMAIN = process.env.SITE_DOMAIN || "";
const AUTH_SECRET = process.env.AUTH_SECRET || "";

if (!REDIS_URL || !REDIS_TOKEN) throw new Error("Upstash env missing");
if (!RESEND_KEY) throw new Error("Resend env missing");
if (!AUTH_SECRET || AUTH_SECRET.length < 32) throw new Error("AUTH_SECRET too short");

function setSecurityHeaders(res) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
}

function ipOf(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  return (xf.split(",")[0] || "").trim() || req.socket?.remoteAddress || "unknown";
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeUsername(u) {
  u = String(u || "").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

function okUsername(u) {
  // 3-20, латиница/цифры/_, без двойных __ подряд
  if (!/^[a-z0-9_]{3,20}$/.test(u)) return false;
  if (u.includes("__")) return false;
  return true;
}

function okName(name) {
  name = String(name || "").trim();
  return name.length >= 1 && name.length <= 40;
}

function okPassword(pw) {
  pw = String(pw || "");
  return pw.length >= 8 && pw.length <= 72;
}

function genCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function pbkdf2Hash(password, salt) {
  // PBKDF2 вместо bcrypt (на Vercel нативные зависимости иногда боль)
  const iter = 150000;
  const keylen = 32;
  const digest = "sha256";
  const dk = crypto.pbkdf2Sync(password, salt, iter, keylen, digest).toString("hex");
  return `pbkdf2$${iter}$${salt}$${dk}`;
}

function pbkdf2Verify(password, stored) {
  try {
    const [tag, iterStr, salt, dk] = String(stored).split("$");
    if (tag !== "pbkdf2") return false;
    const iter = Number(iterStr);
    const keylen = dk.length / 2;
    const digest = "sha256";
    const test = crypto.pbkdf2Sync(password, salt, iter, keylen, digest).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(test, "hex"), Buffer.from(dk, "hex"));
  } catch {
    return false;
  }
}

async function redis(cmd, ...args) {
  const url = `${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${REDIS_TOKEN}` } });
  const j = await r.json();
  if (j.error) throw new Error(`Redis error: ${j.error}`);
  return j;
}

async function rateLimit(req, bucket, limit, windowSec) {
  const ip = ipOf(req);
  const key = `rl:${ip}:${bucket}`;
  const cur = await redis("incr", key);
  if (cur.result === 1) await redis("expire", key, String(windowSec));
  return cur.result <= limit;
}

function setSessionCookie(res, sid) {
  // HttpOnly + SameSite=Lax + Secure (на https)
  const secure = "Secure; ";
  res.setHeader(
    "Set-Cookie",
    `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; ${secure}Max-Age=${60 * 60 * 24 * 30}`
  );
}

function clearSessionCookie(res) {
  const secure = "Secure; ";
  res.setHeader(
    "Set-Cookie",
    `sid=; Path=/; HttpOnly; SameSite=Lax; ${secure}Max-Age=0`
  );
}

function randomSid() {
  return crypto.randomBytes(24).toString("base64url");
}

async function sendMailCode(email, code) {
  // from должен быть verified (у тебя уже настроено)
  const from = `Exuberant <auth@${SITE_DOMAIN || "exuberant.pw"}>`;
  const subject = `Код входа ${SITE_NAME}`;

  const html = `
  <div style="font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial; color:#111;">
    <div style="max-width:520px;margin:0 auto;padding:24px">
      <div style="font-size:14px;opacity:.7;margin-bottom:10px">${SITE_NAME}</div>
      <div style="font-size:28px;font-weight:700;letter-spacing:2px">${code}</div>
      <div style="margin-top:14px;font-size:14px;opacity:.75">Код действителен 5 минут.</div>
    </div>
  </div>`;

  const rr = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ from, to: email, subject, html })
  });

  // Resend иногда возвращает JSON с ошибкой
  if (!rr.ok) {
    const t = await rr.text().catch(() => "");
    throw new Error(`Resend failed: ${rr.status} ${t}`);
  }
}

export default async function handler(req, res) {
  setSecurityHeaders(res);

  if (req.method !== "POST") return res.status(405).end();

  // базовый anti-abuse
  const allow = await rateLimit(req, "auth", 60, 60); // 60 req/min
  if (!allow) return res.status(429).json({ error: "RATE_LIMIT" });

  const action = String(req.query.action || "");
  const body = req.body || {};

  // --- REGISTER: sendCode (email+password -> email code) ---
  if (action === "register_sendCode") {
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!email.includes("@")) return res.status(400).json({ error: "BAD_EMAIL" });
    if (!okPassword(password)) return res.status(400).json({ error: "BAD_PASSWORD" });

    // если уже есть юзер
    const exists = await redis("get", `user:email:${email}`);
    if (exists.result) {
      return res.json({ error: "ACCOUNT_EXISTS" });
    }

    const code = genCode();
    const salt = crypto.randomBytes(16).toString("hex");
    const pwHash = pbkdf2Hash(password, salt);

    await redis(
      "set",
      `pending:${email}`,
      JSON.stringify({ mode: "register", code, pwHash, createdAt: Date.now() }),
      "EX",
      300
    );

    await sendMailCode(email, code);

    return res.json({ ok: true, type: "auth.sentCodeTypeEmailCode" });
  }

  // --- REGISTER: verifyCode ---
  if (action === "register_verifyCode") {
    const email = normalizeEmail(body.email);
    const code = String(body.code || "").trim();

    const p = await redis("get", `pending:${email}`);
    if (!p.result) return res.status(400).json({ error: "NO_PENDING" });

    const parsed = JSON.parse(p.result);
    if (parsed.mode !== "register") return res.status(400).json({ error: "BAD_FLOW" });
    if (parsed.code !== code) return res.status(401).json({ error: "INVALID_CODE" });

    // подтверждено, даем переход на setup
    await redis("set", `pending:${email}`, JSON.stringify({ ...parsed, verified: true }), "EX", 600);

    return res.json({ ok: true, type: "auth.sentCodeTypeSetUpEmailRequired" });
  }

  // --- REGISTER: setup profile (creates user + session) ---
  if (action === "register_setup") {
    const email = normalizeEmail(body.email);
    const name = String(body.name || "").trim();
    const username = normalizeUsername(body.username);

    if (!okName(name)) return res.status(400).json({ error: "BAD_NAME" });
    if (!okUsername(username)) return res.status(400).json({ error: "BAD_USERNAME" });

    const p = await redis("get", `pending:${email}`);
    if (!p.result) return res.status(400).json({ error: "NO_PENDING" });

    const parsed = JSON.parse(p.result);
    if (!parsed.verified) return res.status(403).json({ error: "EMAIL_NOT_VERIFIED" });

    // если email уже успели создать (гонка)
    const exists = await redis("get", `user:email:${email}`);
    if (exists.result) return res.json({ error: "ACCOUNT_EXISTS" });

    // username должен быть свободен
    const u = await redis("get", `user:username:${username}`);
    if (u.result) return res.status(409).json({ error: "USERNAME_TAKEN" });

    const user = {
      email,
      username,
      name,
      avatarUrl: "",
      pwHash: parsed.pwHash,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    await redis("set", `user:email:${email}`, JSON.stringify(user));
    await redis("set", `user:username:${username}`, email);

    await redis("del", `pending:${email}`);

    // создаем сессию
    const sid = randomSid();
    await redis("set", `sess:${sid}`, email, "EX", String(60 * 60 * 24 * 30));
    setSessionCookie(res, sid);

    return res.json({ ok: true });
  }

  // --- LOGIN: email+password ---
  if (action === "login") {
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!email.includes("@")) return res.status(400).json({ error: "BAD_EMAIL" });

    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return res.status(404).json({ error: "NO_ACCOUNT" });

    const user = JSON.parse(u.result);
    if (!pbkdf2Verify(password, user.pwHash)) {
      return res.status(401).json({ error: "BAD_CREDENTIALS" });
    }

    const sid = randomSid();
    await redis("set", `sess:${sid}`, email, "EX", String(60 * 60 * 24 * 30));
    setSessionCookie(res, sid);

    return res.json({ ok: true });
  }

  // --- LOGOUT ---
  if (action === "logout") {
    const cookie = String(req.headers.cookie || "");
    const sid = (cookie.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1];
    if (sid) await redis("del", `sess:${sid}`);
    clearSessionCookie(res);
    return res.json({ ok: true });
  }

  return res.status(404).json({ error: "NOT_FOUND" });
}
