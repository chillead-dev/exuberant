const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(cmd, ...args){
  const r = await fetch(`${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`, {
    headers:{ Authorization:`Bearer ${REDIS_TOKEN}` }
  });
  const j = await r.json();
  if (j.error) throw new Error(`Redis error: ${j.error}`);
  return j;
}

function getSid(req){
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1] || "";
}

function clearSessionCookie(res){
  const secure = "Secure; ";
  res.setHeader("Set-Cookie",
    `sid=; Path=/; HttpOnly; SameSite=Lax; ${secure}Max-Age=0`
  );
}

export default async function handler(req, res){
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");

  const sid = getSid(req);
  if (!sid) return res.status(401).end();

  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).end();
  const email = se.result;

  // LIST
  if (req.method === "GET"){
    const s = await redis("smembers", `sess:user:${email}`);
    const ids = s.result || [];

    // мы не храним createdAt у сессии — добавим сейчас простой timestamp из ключа не получится
    // поэтому показываем "short id" + current placeholder time (чтобы UI был стабильный)
    const now = Date.now();
    const sessions = ids.map(x => ({ idShort: String(x).slice(0,8), createdAt: now }));
    return res.json({ sessions });
  }

  // LOGOUT ALL
  if (req.method === "POST" && String(req.query.action||"") === "logout_all"){
    const s = await redis("smembers", `sess:user:${email}`);
    const ids = s.result || [];
    for (const x of ids){
      await redis("del", `sess:${x}`);
    }
    await redis("del", `sess:user:${email}`);
    clearSessionCookie(res);
    return res.json({ ok:true });
  }

  return res.status(405).end();
}
