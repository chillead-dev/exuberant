import { Redis } from "@upstash/redis";
import { Resend } from "resend";
import crypto from "crypto";

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const resend = new Resend(process.env.RESEND_API_KEY);

function sha(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function genCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  const { action, email, password, code, name, username } = req.body;
  if (!email) return res.json({ error: "email required" });

  // SEND CODE
  if (action === "send_code") {
    if (await redis.get(`email:${email}`))
      return res.json({ error: "email already used" });

    const uid = crypto.randomUUID();
    await redis.set(`email:${email}`, uid);
    await redis.hset(`user:${uid}`, {
      email,
      password: sha(password),
      verified: "0",
    });

    const c = genCode();
    await redis.hset(`code:${email}`, { hash: sha(c) });
    await redis.expire(`code:${email}`, 300);

    await resend.emails.send({
      from: process.env.MAIL_FROM,
      to: email,
      subject: "Exuberant code",
      html: `<h2>${c}</h2>`,
    });

    return res.json({ ok: true });
  }

  // VERIFY CODE
  if (action === "verify_code") {
    const data = await redis.hgetall(`code:${email}`);
    if (!data?.hash) return res.json({ error: "code expired" });
    if (sha(code) !== data.hash) return res.json({ error: "wrong code" });

    await redis.del(`code:${email}`);
    return res.json({ ok: true });
  }

  // FINISH SIGNUP
  if (action === "finish") {
    if (await redis.get(`username:${username}`))
      return res.json({ error: "username taken" });

    const uid = await redis.get(`email:${email}`);
    await redis.hset(`user:${uid}`, { name, username });
    await redis.set(`username:${username}`, uid);

    return res.json({ ok: true });
  }

  res.json({ error: "unknown action" });
}
