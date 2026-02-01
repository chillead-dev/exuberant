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

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  // auth
  const sid = getSid(req);
  if (!sid) return res.status(401).end();
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).end();

  const exact = String(req.query.exact || "") === "1";
  const q = exact ? normalizeUsername(req.query.u) : normalizeUsername(req.query.q);

  if (!q) return res.json({ users: [] });

  if (exact){
    const email = (await redis("get", `user:username:${q}`)).result;
    if (!email) return res.json({ user: null });
    const u = (await redis("get", `user:email:${email}`)).result;
    if (!u) return res.json({ user: null });
    const user = JSON.parse(u);
    return res.json({ user: { username: user.username, name: user.name, avatarUrl: user.avatarUrl || "" } });
  }

  // search (prefix contains)
  let cursor = "0";
  const out = [];
  const limit = 12;
  const target = q;

  // SCAN up to some iterations
  for (let i=0; i<8 && out.length < limit; i++){
    const s = await redis("scan", cursor, "match", "user:username:*", "count", "200");
    cursor = String(s.result?.[0] ?? "0");
    const keys = s.result?.[1] || [];

    for (const k of keys){
      const username = String(k).slice("user:username:".length);
      if (username.includes(target)){
        const email = (await redis("get", k)).result;
        if (!email) continue;
        const u = (await redis("get", `user:email:${email}`)).result;
        if (!u) continue;
        const user = JSON.parse(u);
        out.push({ username: user.username, name: user.name || "", avatarUrl: user.avatarUrl || "" });
        if (out.length >= limit) break;
      }
    }
    if (cursor === "0") break;
  }

  res.json({ users: out });
}
