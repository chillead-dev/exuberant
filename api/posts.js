import crypto from "crypto";
import { marked } from "marked";
import DOMPurify from "isomorphic-dompurify";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(cmd, ...args) {
  const r = await fetch(`${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`, {
    headers: { Authorization: `Bearer ${REDIS_TOKEN}` }
  });
  return r.json();
}

function getSid(req) {
  const c = String(req.headers.cookie || "");
  return (c.match(/(?:^|;\s*)sid=([^;]+)/) || [])[1];
}

function sanitize(md) {
  const html = marked.parse(md, { mangle: false, headerIds: false });
  return DOMPurify.sanitize(html);
}

export default async function handler(req, res) {
  const sid = getSid(req);
  if (!sid) return res.status(401).end();

  const se = await redis("get", `sess:${sid}`);
  if (!se.result) return res.status(401).end();

  const email = se.result;

  if (req.method === "POST") {
    const { title, body } = req.body || {};
    if (!title || !body) return res.status(400).end();

    const id = crypto.randomBytes(8).toString("hex");

    await redis("set", `post:${id}`, JSON.stringify({
      id,
      title: title.trim(),
      body: sanitize(body),
      author: email,
      createdAt: Date.now()
    }));

    await redis("lpush", "posts", id);
    return res.json({ ok: true });
  }

  if (req.method === "GET") {
    const list = await redis("lrange", "posts", 0, 20);
    const posts = [];

    for (const id of list.result || []) {
      const p = await redis("get", `post:${id}`);
      if (p.result) posts.push(JSON.parse(p.result));
    }

    return res.json(posts);
  }

  res.status(405).end();
}
