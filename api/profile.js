const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

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
  return /^[a-z0-9_]{3,20}$/.test(u) && !u.includes("__");
}
function okName(n){
  n = String(n||"").trim();
  return n.length>=1 && n.length<=40;
}
function okAbout(a){
  a = String(a||"");
  return a.length <= 240;
}

const ALLOWED_BADGES = new Set(["premium","verified","early"]);

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  const sid = getSid(req);
  if (!sid) { res.statusCode=401; return res.end(); }

  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { res.statusCode=401; return res.end(); }

  const email = se.result;

  if (req.method === "GET"){
    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return res.end(JSON.stringify({ error:"NO_ACCOUNT" }));
    const user = JSON.parse(u.result);

    return res.end(JSON.stringify({
      email: user.email,
      username: user.username,
      name: user.name,
      avatar: user.avatar || "",
      about: user.about || "",
      badges: user.badges || []
    }));
  }

  if (req.method === "POST"){
    const body = req.body || {};
    const u = await redis("get", `user:email:${email}`);
    if (!u.result) return res.end(JSON.stringify({ ok:false, error:"NO_ACCOUNT" }));
    const user = JSON.parse(u.result);

    const newName = body.name !== undefined ? String(body.name).trim() : user.name;
    const newUsername = body.username !== undefined ? normalizeUsername(body.username) : user.username;
    const newAbout = body.about !== undefined ? String(body.about) : (user.about || "");
    const newBadges = Array.isArray(body.badges) ? body.badges.map(String) : (user.badges || []);

    if (!okName(newName)) return res.end(JSON.stringify({ ok:false, error:"BAD_NAME" }));
    if (!okUsername(newUsername)) return res.end(JSON.stringify({ ok:false, error:"BAD_USERNAME" }));
    if (!okAbout(newAbout)) return res.end(JSON.stringify({ ok:false, error:"BAD_ABOUT" }));

    const filteredBadges = [];
    for (const b of newBadges){
      if (ALLOWED_BADGES.has(b) && !filteredBadges.includes(b)) filteredBadges.push(b);
      if (filteredBadges.length >= 5) break;
    }

    if (newUsername !== user.username){
      const taken = await redis("get", `user:username:${newUsername}`);
      if (taken.result) return res.end(JSON.stringify({ ok:false, error:"USERNAME_TAKEN" }));

      await redis("del", `user:username:${user.username}`);
      await redis("set", `user:username:${newUsername}`, email);
    }

    user.name = newName;
    user.username = newUsername;
    user.about = newAbout;
    user.badges = filteredBadges;
    user.updatedAt = Date.now();

    await redis("set", `user:email:${email}`, JSON.stringify(user));
    return res.end(JSON.stringify({ ok:true }));
  }

  res.statusCode = 405;
  res.end(JSON.stringify({ ok:false, error:"METHOD_NOT_ALLOWED" }));
}
