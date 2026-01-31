import crypto from "crypto";

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;

function redis(cmd, ...args) {
  return fetch(`${REDIS_URL}/${cmd}/${args.map(encodeURIComponent).join("/")}`, {
    headers: {
      Authorization: `Bearer ${REDIS_TOKEN}`
    }
  }).then(r => r.json());
}

function genCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export default async function handler(req, res) {
  const { action } = req.query;
  const body = req.body || {};

  /* sendCode */
  if (action === "sendCode") {
    const code = genCode();

    await redis(
      "set",
      `email:${body.email}`,
      JSON.stringify({
        code,
        verified: false
      }),
      "EX",
      300
    );

    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "Exuberant <auth@exuberant.pw>",
        to: body.email,
        subject: "Код входа Exuberant",
        html: `<div style="font-size:28px;font-weight:700">${code}</div>`
      })
    });

    return res.json({
      _: "auth.sentCode",
      type: "auth.sentCodeTypeEmailCode"
    });
  }

  /* verifyCode */
  if (action === "verifyCode") {
    const data = await redis("get", `email:${body.email}`);
    if (!data.result) return res.status(400).end();

    const parsed = JSON.parse(data.result);
    if (parsed.code !== body.code) {
      return res.status(401).json({ error: "INVALID_CODE" });
    }

    parsed.verified = true;
    await redis("set", `email:${body.email}`, JSON.stringify(parsed), "EX", 600);

    return res.json({
      _: "auth.sentCode",
      type: "auth.sentCodeTypeSetUpEmailRequired",
      forum: "exuberant"
    });
  }

  /* setup profile */
  if (action === "setup") {
    const data = await redis("get", `email:${body.email}`);
    if (!data.result) return res.status(400).end();

    const parsed = JSON.parse(data.result);
    if (!parsed.verified) return res.status(403).end();

    await redis("del", `email:${body.email}`);

    return res.json({ status: "OK" });
  }

  res.status(404).end();
}
