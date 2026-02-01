import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;

const SITE_NAME = process.env.SITE_NAME || "exuberant";
const SITE_DOMAIN = process.env.SITE_DOMAIN || "exuberant.pw";
const AUTH_SECRET = process.env.AUTH_SECRET || "";

if (!REDIS_URL || !REDIS_TOKEN) throw new Error("Upstash env missing");
if (!RESEND_KEY) throw new Error("Resend env missing");
if (!AUTH_SECRET || AUTH_SECRET.length < 32) throw new Error("AUTH_SECRET too short");

function setSecurityHeaders(res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Referrer-Policy","no-referrer");
  res.setHeader("X-Frame-Options","DENY");
}

function ipOf(req){
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  return (xf.split(",")[0] || "").trim() || req.socket?.remoteAddress || "unknown";
}

async function readJson(req){
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

function normalizeEmail(e){ return String(e||"").trim().toLowerCase(); }
function normalizeUsername(u){
  u = String(u||"").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

function okUsername(u){
  return /^[a-z0-9_]{3,20}$/.test(u) && !u.includes("__");
}
function okName(n){
  n = String(n||"").trim();
  return n.length>=1 && n.length<=40;
}
function okPassword(p){
  p = String(p||"");
  return p.length>=8 && p.length<=72;
}
function genCode(){
  return Math.floor(100000 + Math.random()*900000).toString();
}

function pbkdf2Hash(password, salt){
  const iter = 150000;
  const dk = crypto.pbkdf2Sync(password, salt, iter, 32, "sha256").toString("hex");
  return `pbkdf2$${iter}$${salt}$${dk}`;
}
function pbkdf2Verify(password, stored){
  try{
    const [, iter, salt, dk] = stored.split("$");
    const test = crypto.pbkdf2Sync(password, salt, Number(iter), dk.length/2, "sha256").toString("hex");
    return crypto.timingSafeEqual(Buffer.from(test,"hex"), Buffer.from(dk,"hex"));
  }catch{ return false; }
}

async function redis(cmd, ...args){
  const r = await fetch(`${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`,{
    headers:{ Authorization:`Bearer ${REDIS_TOKEN}` }
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j;
}

async function rateLimit(req, bucket, limit, windowSec){
  const key = `rl:${ipOf(req)}:${bucket}`;
  const cur = await redis("incr", key);
  if (cur.result === 1) await redis("expire", key, String(windowSec));
  return cur.result <= limit;
}

function randomSid(){
  return crypto.randomBytes(24).toString("base64url");
}
function setSession(res, sid){
  res.setHeader("Set-Cookie",
    `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${60*60*24*30}`
  );
}
function clearSession(res){
  res.setHeader("Set-Cookie",
    `sid=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`
  );
}

async function sendMail(to, subject, html){
  const from = `Exuberant <auth@${SITE_DOMAIN}>`;
  const r = await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{
      Authorization:`Bearer ${RESEND_KEY}`,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({ from, to, subject, html })
  });
  if (!r.ok) throw new Error("Resend failed");
}

export default async function handler(req,res){
  setSecurityHeaders(res);
  if (req.method !== "POST") return res.status(405).end();

  const action = String(req.query.action||"");
  const body = await readJson(req);

  if (!(await rateLimit(req,"auth",80,60)))
    return res.status(429).json({ok:false,error:"RATE_LIMIT"});

  // REGISTER SEND CODE
  if (action === "register_sendCode"){
    const email = normalizeEmail(body.email);
    const password = body.password;

    if (!email.includes("@")) return res.json({ok:false,error:"BAD_EMAIL"});
    if (!okPassword(password)) return res.json({ok:false,error:"BAD_PASSWORD"});

    if ((await redis("get",`user:email:${email}`)).result)
      return res.json({ok:false,error:"ACCOUNT_EXISTS"});

    const code = genCode();
    const salt = crypto.randomBytes(16).toString("hex");
    const pwHash = pbkdf2Hash(password, salt);

    await redis("set",`pending:${email}`,JSON.stringify({code,pwHash}),"EX",300);

    await sendMail(
      email,
      `Код входа ${SITE_NAME}`,
      `<b>${code}</b><p>Действителен 5 минут</p>`
    );

    return res.json({ok:true});
  }

  // REGISTER VERIFY
  if (action === "register_verifyCode"){
    const email = normalizeEmail(body.email);
    const p = await redis("get",`pending:${email}`);
    if (!p.result) return res.json({ok:false,error:"NO_PENDING"});
    if (JSON.parse(p.result).code !== body.code)
      return res.json({ok:false,error:"INVALID_CODE"});
    await redis("set",`pending:${email}`,JSON.stringify({...JSON.parse(p.result),verified:true}),"EX",600);
    return res.json({ok:true});
  }

  // REGISTER SETUP
  if (action === "register_setup"){
    const email = normalizeEmail(body.email);
    const name = body.name;
    const username = normalizeUsername(body.username);

    if (!okName(name)) return res.json({ok:false,error:"BAD_NAME"});
    if (!okUsername(username)) return res.json({ok:false,error:"BAD_USERNAME"});
    if ((await redis("get",`user:username:${username}`)).result)
      return res.json({ok:false,error:"USERNAME_TAKEN"});

    const p = JSON.parse((await redis("get",`pending:${email}`)).result||"{}");
    if (!p.verified) return res.json({ok:false,error:"NO_PENDING"});

    const user = { email, name, username, pwHash:p.pwHash, createdAt:Date.now() };

    await redis("set",`user:email:${email}`,JSON.stringify(user));
    await redis("set",`user:username:${username}`,email);
    await redis("del",`pending:${email}`);

    const sid = randomSid();
    await redis("set",`sess:${sid}`,email,"EX",60*60*24*30);
    setSession(res,sid);

    return res.json({ok:true});
  }

  // LOGIN
  if (action === "login"){
    const email = normalizeEmail(body.email);
    const u = await redis("get",`user:email:${email}`);
    if (!u.result) return res.json({ok:false,error:"NO_ACCOUNT"});
    if (!pbkdf2Verify(body.password, JSON.parse(u.result).pwHash))
      return res.json({ok:false,error:"BAD_CREDENTIALS"});

    const sid = randomSid();
    await redis("set",`sess:${sid}`,email,"EX",60*60*24*30);
    setSession(res,sid);

    return res.json({ok:true});
  }

  if (action === "logout"){
    clearSession(res);
    return res.json({ok:true});
  }

  return res.status(404).json({ok:false,error:"UNKNOWN_ACTION"});
}
