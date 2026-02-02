import crypto from "crypto";

/**
 * /api/auth?action=...
 * Required ENV:
 * - UPSTASH_REDIS_REST_URL
 * - UPSTASH_REDIS_REST_TOKEN
 * - AUTH_SECRET (>=16 chars)
 * Optional:
 * - RESEND_API_KEY (email codes & 2FA codes)
 * - SITE_DOMAIN, SITE_NAME
 * - ADMIN_EMAIL, ADMIN_KEY (admin actions)
 *
 * Actions:
 * - register_send   POST { email, password }
 * - register_verify POST { email, code }
 * - register_setup  POST { email, name, username }
 * - login           POST { email, password }
 * - login_2fa        POST { ticket, code }
 * - logout          POST
 * - profile_get     GET
 * - profile_set     POST { name?, username?, about?, badges?[] }
 * - avatar_set      POST { dataUrl }
 * - twofa_enable    POST
 * - twofa_disable   POST
 * - admin_user_get  GET  ?u=username&adminKey=...
 * - admin_user_set  POST { adminKey, username, badges?[], ban?:true|false, reason? }
 */

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const RESEND_KEY = process.env.RESEND_API_KEY || "";
const AUTH_SECRET = process.env.AUTH_SECRET || "";

const SITE_DOMAIN = process.env.SITE_DOMAIN || "exuberant.pw";
const SITE_NAME = process.env.SITE_NAME || "Exuberant";

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const ADMIN_KEY = process.env.ADMIN_KEY || "";

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.end(JSON.stringify(obj));
}

function envOk() {
  return !!(REDIS_URL && REDIS_TOKEN && AUTH_SECRET && AUTH_SECRET.length >= 16);
}

async function redis(cmd, ...args) {
  const url = `${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${REDIS_TOKEN}` } });
  const j = await r.json().catch(() => ({}));
  if (j.error) throw new Error(`Redis: ${j.error}`);
  return j;
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
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

function getSid(req) {
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}

function isHttps(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().toLowerCase();
  return proto === "https";
}

function setSid(res, req, sid) {
  const secure = isHttps(req) ? "Secure; " : "";
  res.setHeader(
    "Set-Cookie",
    `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; ${secure}Max-Age=${60 * 60 * 24 * 30}`
  );
}

function clearSid(res, req) {
  const secure = isHttps(req) ? "Secure; " : "";
  res.setHeader(
    "Set-Cookie",
    `sid=; Path=/; HttpOnly; SameSite=Lax; ${secure}Max-Age=0`
  );
}

function normEmail(e) { return String(e || "").trim().toLowerCase(); }
function normUser(u) {
  u = String(u || "").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

function okPassword(p) { p = String(p || ""); return p.length >= 8 && p.length <= 72; }
function okName(n) { n = String(n || "").trim(); return n.length >= 1 && n.length <= 40; }
function okUsername(u) { return /^[a-z0-9_]{3,20}$/.test(u) && !u.includes("__"); }
function okAbout(a) { return String(a || "").length <= 240; }

const ALLOWED_BADGES = new Set(["premium","verified","early","developer"]);
const ALLOWED_PUBLIC_BADGES = new Set(["premium","verified","early"]); // user self-service

function genCode() { return Math.floor(100000 + Math.random() * 900000).toString(); }

// Password hashing v2: PBKDF2 + salt, with v1 fallback
function pwHashV1(password) {
  return crypto.createHmac("sha256", AUTH_SECRET).update(String(password || "")).digest("hex");
}
function pwHashV2(password, saltHex) {
  const iter = 150000;
  const salt = Buffer.from(saltHex, "hex");
  const dk = crypto.pbkdf2Sync(String(password || ""), salt, iter, 32, "sha256");
  return `pbkdf2$${iter}$${saltHex}$${dk.toString("hex")}`;
}
function pwVerify(password, stored) {
  if (typeof stored === "string" && stored.startsWith("pbkdf2$")) {
    try {
      const [, iterStr, saltHex, dkHex] = stored.split("$");
      const iter = Number(iterStr);
      const salt = Buffer.from(saltHex, "hex");
      const dk = crypto.pbkdf2Sync(String(password || ""), salt, iter, dkHex.length / 2, "sha256").toString("hex");
      return crypto.timingSafeEqual(Buffer.from(dk, "hex"), Buffer.from(dkHex, "hex"));
    } catch {
      return false;
    }
  }
  return stored === pwHashV1(password);
}

async function sendEmail(to, subject, html) {
  if (!RESEND_KEY) throw new Error("RESEND_NOT_CONFIGURED");
  const from = `Exuberant <auth@${SITE_DOMAIN}>`;
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to, subject, html })
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`RESEND_${r.status}:${t.slice(0, 160)}`);
  }
}

async function sendCodeEmail(to, code, title = "Код входа") {
  const subject = `${title} ${SITE_NAME}`;
  const html = `<div style="font-family:Arial,sans-serif">
    <div style="font-size:14px;opacity:.7">${SITE_NAME}</div>
    <div style="font-size:28px;font-weight:800;letter-spacing:2px;margin:10px 0">${code}</div>
    <div style="font-size:13px;opacity:.75">Код действует 5 минут.</div>
  </div>`;
  await sendEmail(to, subject, html);
}

async function isBanned(email) {
  const b = await redis("get", `ban:email:${email}`);
  return !!b.result;
}

async function requireAuth(req, res) {
  const sid = getSid(req);
  if (!sid) { json(res, 401, { ok:false, error:"NO_SESSION" }); return null; }
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { json(res, 401, { ok:false, error:"NO_SESSION" }); return null; }
  const email = se.result;

  if (await isBanned(email)) {
    json(res, 403, { ok:false, error:"BANNED" });
    return null;
  }
  return email;
}

function isAdmin(email, adminKey) {
  return !!(ADMIN_EMAIL && ADMIN_KEY && email === ADMIN_EMAIL && adminKey === ADMIN_KEY);
}

export default async function handler(req, res) {
  try {
    const action = String(req.query.action || "");
    const body = await readBody(req);

    if (!envOk()) return json(res, 500, { ok:false, error:"SERVER_MISCONFIGURED" });

    // global RL
    if (!(await rateLimit(req, "auth", 140, 60))) {
      return json(res, 429, { ok:false, error:"RATE_LIMIT" });
    }

    // -------- REGISTER SEND --------
    if (action === "register_send") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const email = normEmail(body.email);
      const password = String(body.password || "");

      if (!email.includes("@")) return json(res, 200, { ok:false, error:"BAD_EMAIL" });
      if (!okPassword(password)) return json(res, 200, { ok:false, error:"BAD_PASSWORD" });

      const exists = await redis("get", `user:email:${email}`);
      if (exists.result) return json(res, 200, { ok:false, error:"ACCOUNT_EXISTS" });

      const code = genCode();
      const saltHex = crypto.randomBytes(16).toString("hex");
      const pw = pwHashV2(password, saltHex);

      await redis("set", `pending:${email}`, JSON.stringify({ code, pw, createdAt: Date.now() }), "EX", 300);

      try { await sendCodeEmail(email, code, "Код регистрации"); }
      catch { return json(res, 200, { ok:false, error:"EMAIL_SEND_FAILED" }); }

      return json(res, 200, { ok:true });
    }

    // -------- REGISTER VERIFY --------
    if (action === "register_verify") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const email = normEmail(body.email);
      const code = String(body.code || "").trim();

      const p = await redis("get", `pending:${email}`);
      if (!p.result) return json(res, 200, { ok:false, error:"NO_PENDING" });

      const data = JSON.parse(p.result);
      if (data.code !== code) return json(res, 200, { ok:false, error:"INVALID_CODE" });

      data.verified = true;
      await redis("set", `pending:${email}`, JSON.stringify(data), "EX", 600);

      return json(res, 200, { ok:true });
    }

    // -------- REGISTER SETUP --------
    if (action === "register_setup") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const email = normEmail(body.email);
      const name = String(body.name || "").trim();
      const username = normUser(body.username);

      if (!okName(name)) return json(res, 200, { ok:false, error:"BAD_NAME" });
      if (!okUsername(username)) return json(res, 200, { ok:false, error:"BAD_USERNAME" });

      const p = await redis("get", `pending:${email}`);
      if (!p.result) return json(res, 200, { ok:false, error:"NO_PENDING" });
      const data = JSON.parse(p.result);
      if (!data.verified) return json(res, 200, { ok:false, error:"NO_PENDING" });

      const taken = await redis("get", `user:username:${username}`);
      if (taken.result) return json(res, 200, { ok:false, error:"USERNAME_TAKEN" });

      const user = {
        email,
        username,
        name,
        about: "",
        avatar: "",
        badges: [],

        twofa: { enabled: false },

        pw: data.pw,
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      await redis("set", `user:email:${email}`, JSON.stringify(user));
      await redis("set", `user:username:${username}`, email);
      await redis("del", `pending:${email}`);

      const sid = crypto.randomBytes(24).toString("hex");
      await redis("set", `sess:${sid}`, email, "EX", String(60*60*24*30));
      setSid(res, req, sid);

      return json(res, 200, { ok:true });
    }

    // -------- LOGIN --------
    if (action === "login") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });
      if (!(await rateLimit(req, "login", 35, 60))) return json(res, 429, { ok:false, error:"RATE_LIMIT" });

      const email = normEmail(body.email);
      const password = String(body.password || "");

      if (!email.includes("@")) return json(res, 200, { ok:false, error:"BAD_EMAIL" });

      if (await isBanned(email)) return json(res, 403, { ok:false, error:"BANNED" });

      const u = await redis("get", `user:email:${email}`);
      if (!u.result) return json(res, 200, { ok:false, error:"NO_ACCOUNT" });

      const user = JSON.parse(u.result);
      if (!pwVerify(password, user.pw)) return json(res, 200, { ok:false, error:"BAD_CREDENTIALS" });

      // migrate v1->v2 silently if needed
      if (typeof user.pw === "string" && !user.pw.startsWith("pbkdf2$")) {
        const saltHex = crypto.randomBytes(16).toString("hex");
        user.pw = pwHashV2(password, saltHex);
        user.updatedAt = Date.now();
        await redis("set", `user:email:${email}`, JSON.stringify(user));
      }

      // 2FA
      if (user.twofa?.enabled) {
        const ticket = crypto.randomBytes(16).toString("hex");
        const code = genCode();

        await redis("set", `2fa:${ticket}`, JSON.stringify({ email, code, createdAt: Date.now() }), "EX", 300);

        try { await sendCodeEmail(email, code, "2FA код"); }
        catch { return json(res, 200, { ok:false, error:"EMAIL_SEND_FAILED" }); }

        return json(res, 200, { ok:false, error:"2FA_REQUIRED", ticket });
      }

      const sid = crypto.randomBytes(24).toString("hex");
      await redis("set", `sess:${sid}`, email, "EX", String(60*60*24*30));
      setSid(res, req, sid);

      return json(res, 200, { ok:true });
    }

    // -------- LOGIN 2FA --------
    if (action === "login_2fa") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });
      if (!(await rateLimit(req, "login2fa", 40, 60))) return json(res, 429, { ok:false, error:"RATE_LIMIT" });

      const ticket = String(body.ticket || "");
      const code = String(body.code || "").trim();

      const r = await redis("get", `2fa:${ticket}`);
      if (!r.result) return json(res, 200, { ok:false, error:"2FA_EXPIRED" });

      const data = JSON.parse(r.result);
      if (data.code !== code) return json(res, 200, { ok:false, error:"2FA_BAD_CODE" });

      if (await isBanned(data.email)) return json(res, 403, { ok:false, error:"BANNED" });

      await redis("del", `2fa:${ticket}`);

      const sid = crypto.randomBytes(24).toString("hex");
      await redis("set", `sess:${sid}`, data.email, "EX", String(60*60*24*30));
      setSid(res, req, sid);

      return json(res, 200, { ok:true });
    }

    // -------- LOGOUT --------
    if (action === "logout") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });
      clearSid(res, req);
      return json(res, 200, { ok:true });
    }

    // -------- PROFILE GET --------
    if (action === "profile_get") {
      const email = await requireAuth(req, res);
      if (!email) return;

      const u = await redis("get", `user:email:${email}`);
      if (!u.result) return json(res, 200, { ok:false, error:"NO_ACCOUNT" });

      const user = JSON.parse(u.result);
      return json(res, 200, { ok:true, user: {
        email: user.email,
        username: user.username,
        name: user.name,
        about: user.about || "",
        avatar: user.avatar || "",
        badges: user.badges || [],
        twofa: { enabled: !!user.twofa?.enabled }
      }});
    }

    // -------- PROFILE SET --------
    if (action === "profile_set") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });
      const email = await requireAuth(req, res);
      if (!email) return;

      const u = await redis("get", `user:email:${email}`);
      if (!u.result) return json(res, 200, { ok:false, error:"NO_ACCOUNT" });
      const user = JSON.parse(u.result);

      const newName = body.name !== undefined ? String(body.name).trim() : user.name;
      const newUsername = body.username !== undefined ? normUser(body.username) : user.username;
      const newAbout = body.about !== undefined ? String(body.about) : (user.about || "");
      const newBadges = Array.isArray(body.badges) ? body.badges.map(String) : (user.badges || []);

      if (!okName(newName)) return json(res, 200, { ok:false, error:"BAD_NAME" });
      if (!okUsername(newUsername)) return json(res, 200, { ok:false, error:"BAD_USERNAME" });
      if (!okAbout(newAbout)) return json(res, 200, { ok:false, error:"BAD_ABOUT" });

      if (newUsername !== user.username) {
        const taken = await redis("get", `user:username:${newUsername}`);
        if (taken.result) return json(res, 200, { ok:false, error:"USERNAME_TAKEN" });

        await redis("del", `user:username:${user.username}`);
        await redis("set", `user:username:${newUsername}`, email);
      }

      const filtered = [];
      for (const b of newBadges) {
        // users can't set developer badge themselves
        if (ALLOWED_PUBLIC_BADGES.has(b) && !filtered.includes(b)) filtered.push(b);
        if (filtered.length >= 5) break;
      }

      user.name = newName;
      user.username = newUsername;
      user.about = newAbout;
      user.badges = filtered;
      user.updatedAt = Date.now();

      await redis("set", `user:email:${email}`, JSON.stringify(user));
      return json(res, 200, { ok:true });
    }

    // -------- AVATAR SET (dataUrl) --------
    if (action === "avatar_set") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });
      const email = await requireAuth(req, res);
      if (!email) return;

      const dataUrl = String(body.dataUrl || "");
      if (!dataUrl.startsWith("data:image/")) return json(res, 200, { ok:false, error:"BAD_IMAGE" });
      if (dataUrl.length > 2_000_000) return json(res, 200, { ok:false, error:"TOO_LARGE" });

      const u = await redis("get", `user:email:${email}`);
      if (!u.result) return json(res, 200, { ok:false, error:"NO_ACCOUNT" });

      const user = JSON.parse(u.result);
      user.avatar = dataUrl;
      user.updatedAt = Date.now();
      await redis("set", `user:email:${email}`, JSON.stringify(user));

      return json(res, 200, { ok:true });
    }

    // -------- 2FA enable/disable --------
    if (action === "twofa_enable") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });
      const email = await requireAuth(req, res); if (!email) return;
      const u = await redis("get", `user:email:${email}`);
      if (!u.result) return json(res, 200, { ok:false, error:"NO_ACCOUNT" });
      const user = JSON.parse(u.result);
      user.twofa = { enabled: true };
      user.updatedAt = Date.now();
      await redis("set", `user:email:${email}`, JSON.stringify(user));
      return json(res, 200, { ok:true });
    }

    if (action === "twofa_disable") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });
      const email = await requireAuth(req, res); if (!email) return;
      const u = await redis("get", `user:email:${email}`);
      if (!u.result) return json(res, 200, { ok:false, error:"NO_ACCOUNT" });
      const user = JSON.parse(u.result);
      user.twofa = { enabled: false };
      user.updatedAt = Date.now();
      await redis("set", `user:email:${email}`, JSON.stringify(user));
      return json(res, 200, { ok:true });
    }

    // -------- ADMIN: get user --------
    if (action === "admin_user_get") {
      const email = await requireAuth(req, res); if (!email) return;
      const adminKey = String(req.query.adminKey || "");
      if (!isAdmin(email, adminKey)) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      const u = normUser(req.query.u || "");
      const em = (await redis("get", `user:username:${u}`)).result;
      if (!em) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const raw = (await redis("get", `user:email:${em}`)).result;
      if (!raw) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const user = JSON.parse(raw);
      const banned = await isBanned(em);

      return json(res, 200, { ok:true, user: {
        email: user.email,
        username: user.username,
        name: user.name,
        badges: user.badges || [],
        banned
      }});
    }

    // -------- ADMIN: set user (badges/ban) --------
    if (action === "admin_user_set") {
      if (req.method !== "POST") return json(res, 405, { ok:false, error:"METHOD" });

      const email = await requireAuth(req, res); if (!email) return;
      const adminKey = String(body.adminKey || "");
      if (!isAdmin(email, adminKey)) return json(res, 403, { ok:false, error:"FORBIDDEN" });

      const u = normUser(body.username || "");
      const em = (await redis("get", `user:username:${u}`)).result;
      if (!em) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const raw = (await redis("get", `user:email:${em}`)).result;
      if (!raw) return json(res, 200, { ok:false, error:"NOT_FOUND" });

      const user = JSON.parse(raw);

      if (Array.isArray(body.badges)) {
        const filtered = [];
        for (const b of body.badges.map(String)) {
          if (ALLOWED_BADGES.has(b) && !filtered.includes(b)) filtered.push(b);
          if (filtered.length >= 8) break;
        }
        user.badges = filtered;
      }

      if (body.ban === true) {
        await redis("set", `ban:email:${em}`, JSON.stringify({ reason: String(body.reason || "") }), "EX", String(60*60*24*365));
      }
      if (body.ban === false) {
        await redis("del", `ban:email:${em}`);
      }

      user.updatedAt = Date.now();
      await redis("set", `user:email:${em}`, JSON.stringify(user));

      return json(res, 200, { ok:true });
    }

    return json(res, 404, { ok:false, error:"UNKNOWN_ACTION" });
  } catch (e) {
    return json(res, 500, { ok:false, error:"SERVER_ERROR", detail: String(e?.message || e) });
  }
}
