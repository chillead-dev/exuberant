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

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  const email = await requireAuth(req, res);
  if (!email) return;

  if (req.method !== "POST"){
    res.statusCode = 405;
    return res.end(JSON.stringify({ ok:false, error:"METHOD_NOT_ALLOWED" }));
  }

  const body = req.body || {};
  const dataUrl = String(body.dataUrl || "");

  // allow only data:image + size limit
  if (!dataUrl.startsWith("data:image/")) return res.end(JSON.stringify({ ok:false, error:"BAD_IMAGE" }));
  if (dataUrl.length > 2_000_000) return res.end(JSON.stringify({ ok:false, error:"TOO_LARGE" }));

  const uRaw = (await redis("get", `user:email:${email}`)).result;
  if (!uRaw) return res.end(JSON.stringify({ ok:false, error:"NO_ACCOUNT" }));

  const user = JSON.parse(uRaw);
  user.avatar = dataUrl;
  user.updatedAt = Date.now();

  await redis("set", `user:email:${email}`, JSON.stringify(user));
  return res.end(JSON.stringify({ ok:true }));
}
