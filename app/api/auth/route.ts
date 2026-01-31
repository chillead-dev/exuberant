import { Redis } from "@upstash/redis";
import crypto from "crypto";
import { Resend } from "resend";
import { NextResponse } from "next/server";

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

const resend = new Resend(process.env.RESEND_API_KEY!);

function sha(s: string) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function code6() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export async function POST(req: Request) {
  const { action, email, password, code, name, username } = await req.json();

  if (!email) return NextResponse.json({ error: "email required" });

  // SEND CODE
  if (action === "send_code") {
    const exists = await redis.get(`email:${email}`);
    if (exists) return NextResponse.json({ error: "email already used" });

    const uid = crypto.randomUUID();
    await redis.set(`email:${email}`, uid);
    await redis.hset(`user:${uid}`, {
      email,
      password: sha(password),
      verified: "0",
    });

    const c = code6();
    await redis.hset(`code:${email}`, { hash: sha(c), attempts: "0" });
    await redis.expire(`code:${email}`, 300);

    await resend.emails.send({
      from: process.env.MAIL_FROM!,
      to: email,
      subject: "Exuberant code",
      html: `<h2>${c}</h2>`,
    });

    return NextResponse.json({ ok: true });
  }

  // VERIFY CODE
  if (action === "verify_code") {
    const data = await redis.hgetall(`code:${email}`);
    if (!data?.hash) return NextResponse.json({ error: "code expired" });
    if (sha(code) !== data.hash) return NextResponse.json({ error: "wrong code" });

    const uid = await redis.get(`email:${email}`);
    await redis.hset(`user:${uid}`, { verified: "1" });
    await redis.del(`code:${email}`);

    return NextResponse.json({ ok: true });
  }

  // FINISH
  if (action === "finish") {
    const uid = await redis.get(`email:${email}`);
    if (!uid) return NextResponse.json({ error: "no session" });

    const taken = await redis.get(`username:${username}`);
    if (taken) return NextResponse.json({ error: "username taken" });

    await redis.hset(`user:${uid}`, { name, username });
    await redis.set(`username:${username}`, uid);

    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "unknown action" });
}
