import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;

const SITE_NAME = process.env.SITE_NAME || "exuberant";
const SITE_DOMAIN = process.env.SITE_DOMAIN || "";
const AUTH_SECRET = process.env.AUTH_SECRET || "";

const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY || "";

if (!REDIS_URL || !REDIS_TOKEN) throw new Error("Upstash env missing");
if (!RESEND_KEY) throw new Error("Resend env missing");
if (!AUTH_SECRET || AUTH_SECRET.length < 32) throw new Error("AUTH_SECRET too short");

function setSecurityHeaders(res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Referrer-Policy","no-referrer");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("Permissions-Policy","geolocation=(), microphone=(), camera=()");
}

function ipOf(req){
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  return (xf.split(",")[0] || "").trim() || req.socket?.remoteAddress || "unknown";
}

function normalizeEmail(email){ return String(email||"").trim().toLowerCase(); }
function normalizeUsername(u){
  u = String(u||"").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

function okUsername(u){
  if (!/^[a-z0-9_]{3,20}$/.test(u)) return false;
  if (u.includes("__")) return false;
  return true;
}
function okName(n){ n=String(n||"").trim(); return n.length>=1 && n.length<=40; }
function okPassword(p){ p=String(p||""); return p.length>=8 && p.length<=72; }

function genCode(){ return Math.floor(100000 + Math.random()*900000).toString(); }

function pbkdf2Hash(password, salt){
  const iter = 150000, keylen=32, digest="sha256";
  const dk = crypto.pbkdf2Sync(password, salt, iter, keylen, digest).toString("hex");
  return `pbkdf2$${iter}$${salt}$${dk}`;
}
function pbkdf2Verify(password, stored){
  try{
    const [tag, iterStr, salt, dk] = String(stored).split("$");
    if (tag !== "pbkdf2") return false;
    const iter = Number(iterStr);
    const keylen = dk.length/2;
    const test = crypto.pbkdf2Sync(password, salt, iter, keylen, "sha256").toString("hex");
    return crypto.timingSafeEqual(Buffer.from(test,"hex"), Buffer.from(dk,"hex"));
  }catch{return false;}
}

async function redis(cmd, ...args){
  const url = `${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`;
  const r = await fetch(url, { headers:{ Authorization:`Bearer ${REDIS_TOKEN}` }});
  const j = await r.json();
  if (j.error) throw new Error(`Redis error: ${j.error}`);
  return j;
}

async function rateLimit(req, bucket, limit, windowSec){
  const ip = ipOf(req);
  const key = `rl:${ip}:${bucket}`;
  const cur = await redis("incr", key);
  if (cur.result === 1) await redis("expire", key, String(windowSec));
  return cur.result <= limit;
}

async function verifyCaptcha(token, ip){
  if (!TURNSTILE_SECRET) return true; // если не настроено — не блокируем (но лучше настроить)
  const t = String(token || "");
  if (!t) return false;

  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method:"POST",
    headers:{ "Content-Type":"application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      secret: TURNSTILE_SECRET,
      response: t,
      remoteip: ip
    })
  });
  const j = await resp.json().catch(()=>({}));
  return !!j.success;
}

function setSessionCookie(res, sid){
  const secure = "Secure; ";
  res.setHeader("Set-Cookie",
    `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; ${secure}Max-Age=${60*60*24*30}`
  );
}
function clearSessionCookie(res){
  const secure = "Secure; ";
  res.setHeader("Set-Cookie",
    `sid=; Path=/; HttpOnly; SameSite=Lax; ${secure}Max-Age=0`
  );
}
function randomSid(){ return crypto.randomBytes(24).toString("base64url"); }

function sidFromReq(req){
  const cookie = String(req.headers.cookie || "");
  return (cookie.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}

async function logEvent(type, email, ip){
  const key = `log:${Date.now()}:${crypto.randomBytes(4).toString("hex")}`;
  await redis("set", key, JSON.stringify({ type, email, ip }));
  await redis("expire", key, "2592000"); // 30 days
}

async function sendMail(to, subject, html){
  const from = `Exuberant <auth@${SITE_DOMAIN || "exuberant.pw"}>`;
  const rr = await fetch("https://api.resend.com/emails", {
    method:"POST",
    headers:{ Authorization:`Bearer ${RESEND_KEY}`, "Content-Type":"application/json" },
    body: JSON.stringify({ from, to, subject, html })
  });
  if (!rr.ok){
    const t = await rr.text().catch(()=> "");
    throw new Error(`Resend failed: ${rr.status} ${t}`);
  }
}

async function addSessionIndex(email, sid){
  await redis("sadd", `sess:user:${email}`, sid);
  await redis("expire", `sess:user:${email}`, String(60*60*24*30));
}

async function removeSessionIndex(email, sid){
  await redis("srem", `sess:user:${email}`, sid);
}

export default async function handler(req, res){
  setSecurityHeaders(res);

  if (req.method !== "POST") return res.status(405).end();

  // общий лимит
  if (!(await rateLimit(req, "auth", 80, 60))) return res.status(429).json({ error:"RATE_LIMIT" });

  const ip = ipOf(req);
  const action = String(req.query.action || "");
  const body = req.body || {};

  // --- REGISTER: sendCode ---
  if (action === "register_sendCode"){
    if (!(await verifyCaptcha(body.captcha, ip))) return res.status(403).json({ error:"CAPTCHA_FAILED" });

    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    if (!email.includes("@")) return res.status(400).json({ error:"BAD_EMAIL" });
    if (!okPassword(password)) return res.status(400).json({ error:"BAD_PASSWORD" });

    const exists = await redis("get", `user:email:${email}`);
    if (exists.result) return res.json({ error:"ACCOUNT_EXISTS" });

    const code = genCode();
    const salt = crypto.randomBytes(16).toString("hex");
    const pwHash = pbkdf2Hash(password, salt);

    await redis("set", `pending:${email}`, JSON.stringify({ mode:"register", code, pwHash, createdAt:Date.now() }), "EX", 300);

    await sendMail(email, `Код входа ${SITE_NAME}`,
      `<div style="font-family:Inter,system-ui;color:#111">
        <div style="max-width:520px;margin:0 auto;padding:24px">
          <div style="font-size:14px;opacity:.7;margin-bottom:10px">${SITE_NAME}</div>
          <div style="font-size:28px;font-weight:800;letter-spacing:2px">${code}</div>
          <div style="margin-top:14px;font-size:14px;opacity:.75">Код действителен 5 минут.</div>
        </div>
      </div>`
    );

    await logEvent("register_sendCode", email, ip);
    return res.json({ ok:true });
  }

  // --- REGISTER: verifyCode ---
  if (action === "register_verifyCode"){
    const email = normalizeEmail(body.email);
    const code = String(body.code || "").trim();

    const p = await redis("get", `pending:${email}`);
    if (!p.result) return res.status(400).json({ error:"NO_PENDING" });

    const parsed = JSON.parse(p.result);
    if (parsed.mode !== "register") return res.status(400).json({ error:"BAD_FLOW" });
    if (parsed.code !== code) return res.status(401).json({ error:"INVALID_CODE" });

    await redis("set", `pending:${email}`, JSON.stringify({ ...parsed, verified:true }), "EX", 600);
    await logEvent("register_verifyCode", email, ip);
    return res.json({ ok:true });
  }

  // --- REGISTER: setup ---
  if (action === "register_setup"){
    const email = normalizeEmail(body.email);
    const name = String(body.name||"").trim();
    const username = normalizeUsername(body.username);

    if (!okName(name)) return res.status(400).json({ error:"BAD_NAME" });
    if (!okUsername(username)) return res.status(400).json({ error:"BAD_USERNAME" });

    const p = await redis("get", `pending:${email}`);
    if (!p.result) return res.status(400).json({ error:"NO_PENDING" });

    const parsed = JSON.parse(p.result);
    if (!parsed.verified) return res.status(403).json({ error:"EMAIL_NOT_VERIFIED" });

    const exists = await redis("get", `user:email:${email}`);
    if (exists.result) return res.json({ error:"ACCOUNT_EXISTS" });

    const taken = await redis("get", `user:username:${username}`);
    if (taken.result) return res.status(409).json({ error:"USERNAME_TAKEN" });

    const user = {
      email,
      username,
      name,
      avatarUrl:"",
      pwHash: parsed.pwHash,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    await redis("set", `user:email:${email}`, JSON.stringify(user));
    await redis("set", `user:username:${username}`, email);
    await redis("del", `pending:${email}`);

    const sid = randomSid();
    await redis("set", `sess:${sid}`, email, "EX", String(60*60*24*30));
    await addSessionIndex(email, sid);
    setSessionCookie(res, sid);

    await logEvent("register_setup", email, ip);
    return res.json({ ok:true });
  }

  // --- LOGIN ---
  if (action === "login"){
    if (!(await verifyCaptcha(body.captcha, ip))) return res.status(403).json({ error:"CAPTCHA_FAILED" });

    // отдельный лимит на логин
    if (!(await rateLimit(req, "login", 20, 60))) return res.status(429).json({ error:"RATE_LIMIT" });

    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    if (!email.includes("@")) return res.status(400).json({ error:"BAD_EMAIL" });

    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return res.status(404).json({ error:"NO_ACCOUNT" });

    const user = JSON.parse(u.result);
    if (!pbkdf2Verify(password, user.pwHash)) return res.status(401).json({ error:"BAD_CREDENTIALS" });

    const sid = randomSid();
    await redis("set", `sess:${sid}`, email, "EX", String(60*60*24*30));
    await addSessionIndex(email, sid);
    setSessionCookie(res, sid);

    await logEvent("login", email, ip);
    return res.json({ ok:true });
  }

  // --- LOGOUT ---
  if (action === "logout"){
    const sid = sidFromReq(req);
    if (sid){
      const se = await redis("get", `sess:${sid}`);
      if (se.result){
        await removeSessionIndex(se.result, sid);
      }
      await redis("del", `sess:${sid}`);
    }
    clearSessionCookie(res);
    return res.json({ ok:true });
  }

  // --- PASSWORD RESET REQUEST ---
  if (action === "password_reset_request"){
    if (!(await verifyCaptcha(body.captcha, ip))) return res.status(403).json({ error:"CAPTCHA_FAILED" });

    if (!(await rateLimit(req, "reset", 10, 60))) return res.status(429).json({ error:"RATE_LIMIT" });

    const email = normalizeEmail(body.email);
    const u = await redis("get", `user:email:${email}`);

    // не палим существование аккаунта
    if (!u.result) return res.json({ ok:true });

    const token = crypto.randomBytes(32).toString("hex");
    await redis("set", `reset:${token}`, email, "EX", 900);

    const link = `https://${SITE_DOMAIN}/reset.html?token=${token}`;
    await sendMail(email, `Сброс пароля ${SITE_NAME}`,
      `<div style="font-family:Inter,system-ui;color:#111">
        <div style="max-width:520px;margin:0 auto;padding:24px">
          <div style="font-size:14px;opacity:.7;margin-bottom:10px">${SITE_NAME}</div>
          <div style="font-size:16px;font-weight:800;margin-bottom:10px">Смена пароля</div>
          <div style="font-size:14px;opacity:.85;margin-bottom:12px">Ссылка действует 15 минут.</div>
          <a href="${link}" style="word-break:break-all">${link}</a>
        </div>
      </div>`
    );

    await logEvent("password_reset_request", email, ip);
    return res.json({ ok:true });
  }

  // --- PASSWORD RESET CONFIRM ---
  if (action === "password_reset_confirm"){
    if (!(await rateLimit(req, "reset_confirm", 20, 60))) return res.status(429).json({ error:"RATE_LIMIT" });

    const token = String(body.token||"");
    const password = String(body.password||"");
    if (!token) return res.status(400).json({ error:"INVALID_TOKEN" });
    if (!okPassword(password)) return res.status(400).json({ error:"BAD_PASSWORD" });

    const r = await redis("get", `reset:${token}`);
    if (!r.result) return res.status(400).json({ error:"INVALID_TOKEN" });

    const email = r.result;
    const u0 = await redis("get", `user:email:${email}`);
    if (!u0.result) return res.status(404).json({ error:"NO_ACCOUNT" });

    const user = JSON.parse(u0.result);
    const salt = crypto.randomBytes(16).toString("hex");
    user.pwHash = pbkdf2Hash(password, salt);
    user.updatedAt = Date.now();

    await redis("set", `user:email:${email}`, JSON.stringify(user));
    await redis("del", `reset:${token}`);

    await logEvent("password_reset_confirm", email, ip);
    return res.json({ ok:true });
  }

  return res.status(404).json({ error:"NOT_FOUND" });
}
