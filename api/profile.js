const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

function setSecurityHeaders(res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Referrer-Policy","no-referrer");
  res.setHeader("X-Frame-Options","DENY");
}

async function redis(cmd, ...args){
  const url = `${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`;
  const r = await fetch(url, { headers:{ Authorization:`Bearer ${REDIS_TOKEN}` }});
  const j = await r.json();
  if (j.error) throw new Error(`Redis error: ${j.error}`);
  return j;
}

function getSid(req){
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}

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
function okName(name){
  name = String(name||"").trim();
  return name.length>=1 && name.length<=40;
}
function okAvatarUrl(url){
  url = String(url||"").trim();
  if (!url) return true;
  if (!/^https:\/\/[^\s]{5,300}$/.test(url)) return false;
  return true;
}

export default async function handler(req, res){
  setSecurityHeaders(res);

  const sid = getSid(req);
  if (!sid) return res.status(401).json({ error:"NO_SESSION" });

  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).json({ error:"NO_SESSION" });

  const email = se.result;

  if (req.method === "GET"){
    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return res.status(404).json({ error:"NO_ACCOUNT" });
    const user = JSON.parse(u.result);
    return res.json({
      email: user.email,
      username: user.username,
      name: user.name,
      avatarUrl: user.avatarUrl || ""
    });
  }

  if (req.method === "POST"){
    const body = req.body || {};
    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return res.status(404).json({ error:"NO_ACCOUNT" });

    const user = JSON.parse(u.result);

    const newName = body.name !== undefined ? String(body.name).trim() : user.name;
    const newUsername = body.username !== undefined ? normalizeUsername(body.username) : user.username;
    const newAvatarUrl = body.avatarUrl !== undefined ? String(body.avatarUrl).trim() : (user.avatarUrl || "");

    if (!okName(newName)) return res.status(400).json({ error:"BAD_NAME" });
    if (!okUsername(newUsername)) return res.status(400).json({ error:"BAD_USERNAME" });
    if (!okAvatarUrl(newAvatarUrl)) return res.status(400).json({ error:"BAD_AVATAR_URL" });

    if (newUsername !== user.username){
      const taken = await redis("get", `user:username:${newUsername}`);
      if (taken.result) return res.status(409).json({ error:"USERNAME_TAKEN" });

      await redis("del", `user:username:${user.username}`);
      await redis("set", `user:username:${newUsername}`, email);
    }

    user.name = newName;
    user.username = newUsername;
    user.avatarUrl = newAvatarUrl;
    user.updatedAt = Date.now();

    await redis("set", `user:email:${email}`, JSON.stringify(user));
    return res.json({ ok:true });
  }

  return res.status(405).end();
}
