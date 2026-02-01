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

  const sid = getSid(req);
  if (!sid) return res.status(401).end();
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).end();
  const myEmail = se.result;

  if (req.method === "GET"){
    const u = normalizeUsername(req.query.u);
    if (!u) return res.status(400).json({ error:"BAD_USER" });

    const email = (await redis("get", `user:username:${u}`)).result;
    if (!email) return res.json({ pubJwk: null });

    const userRaw = (await redis("get", `user:email:${email}`)).result;
    if (!userRaw) return res.json({ pubJwk: null });

    const user = JSON.parse(userRaw);
    return res.json({ pubJwk: user.pubJwk || null });
  }

  if (req.method === "POST"){
    const body = req.body || {};
    const pubJwk = body.pubJwk;

    // минимальная валидация JWK (P-256 ECDH public)
    if (!pubJwk || pubJwk.kty !== "EC" || pubJwk.crv !== "P-256" || !pubJwk.x || !pubJwk.y){
      return res.status(400).json({ ok:false, error:"BAD_KEY" });
    }

    const userRaw = (await redis("get", `user:email:${myEmail}`)).result;
    if (!userRaw) return res.status(404).json({ ok:false, error:"NO_ACCOUNT" });

    const user = JSON.parse(userRaw);
    user.pubJwk = pubJwk;
    user.updatedAt = Date.now();

    await redis("set", `user:email:${myEmail}`, JSON.stringify(user));
    return res.json({ ok:true });
  }

  return res.status(405).end();
}
