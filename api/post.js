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

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  const sid = getSid(req);
  if (!sid) { res.statusCode=401; return res.end(); }
  const se = await redis("get", `sess:${sid}`);
  if (!se.result) { res.statusCode=401; return res.end(); }

  const id = String(req.query.id || "");
  if (!id) return res.end(JSON.stringify({ ok:false, error:"BAD_ID" }));

  const p = await redis("get", `post:${id}`);
  if (!p.result) return res.end(JSON.stringify({ ok:false, error:"NOT_FOUND" }));

  return res.end(JSON.stringify({ ok:true, post: JSON.parse(p.result) }));
}
