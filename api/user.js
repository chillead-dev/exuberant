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

async function requireAuth(req, res){
  const sid = getSid(req);
  if (!sid) { res.statusCode = 401; res.end(); return null; }
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { res.statusCode = 401; res.end(); return null; }
  return se.result;
}

function norm(u){
  u = String(u||"").trim().toLowerCase();
  if (u.startsWith("@")) u = u.slice(1);
  return u;
}

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  const ok = await requireAuth(req, res);
  if (!ok) return;

  const u = norm(req.query.u);
  if (!u) return res.end(JSON.stringify({ ok:false, error:"BAD_USER" }));

  const email = (await redis("get", `user:username:${u}`)).result;
  if (!email) return res.end(JSON.stringify({ ok:false, error:"NOT_FOUND" }));

  const raw = (await redis("get", `user:email:${email}`)).result;
  if (!raw) return res.end(JSON.stringify({ ok:false, error:"NOT_FOUND" }));

  const user = JSON.parse(raw);

  return res.end(JSON.stringify({
    ok:true,
    user:{
      username: user.username,
      name: user.name || "",
      avatar: user.avatar || "",
      badges: user.badges || [],
      about: user.about || ""
    }
  }));
}
