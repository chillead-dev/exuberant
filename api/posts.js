import { requireAuth, redis } from "./_lib.js";

export default async function handler(req,res){
  const email = await requireAuth(req,res);

  if (req.method === "POST"){
    const { title, body } = req.body || {};
    if (!title || title.length < 3)
      return res.json({ ok:false, error:"BAD_TITLE" });
    if (!body || body.length < 10)
      return res.json({ ok:false, error:"BAD_BODY" });

    const id = Date.now().toString();
    await redis("set",`post:${id}`,JSON.stringify({ id,title,body,email }));
    await redis("lpush","posts",id);
    return res.json({ ok:true });
  }

  if (req.method === "GET"){
    const ids = (await redis("lrange","posts","0","20")).result||[];
    const posts=[];
    for (const id of ids){
      const p = await redis("get",`post:${id}`);
      if (p.result) posts.push(JSON.parse(p.result));
    }
    return res.json({ posts });
  }
}
