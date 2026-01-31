import express from "express";
import Redis from "ioredis";
import bcrypt from "bcrypt";
import { Resend } from "resend";
import crypto from "crypto";

const app = express();
app.use(express.json());

const redis = new Redis("redis://127.0.0.1:6379");
const resend = new Resend("RESEND_API_KEY");

function genCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/* 1. sendCode */
app.post("/auth/sendCode", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).end();

  const code = genCode();
  const hash = await bcrypt.hash(password, 10);

  await redis.set(
    `email:${email}`,
    JSON.stringify({
      code,
      password: hash,
      verified: false
    }),
    "EX",
    300
  );

  await resend.emails.send({
    from: "Exuberant <auth@exuberant.app>",
    to: email,
    subject: "Код входа Exuberant",
    html: `<h2>${code}</h2>`
  });

  res.json({
    _: "auth.sentCode",
    type: "auth.sentCodeTypeEmailCode"
  });
});

/* 2. verifyCode */
app.post("/auth/verifyCode", async (req, res) => {
  const { email, code } = req.body;
  const data = await redis.get(`email:${email}`);
  if (!data) return res.status(400).end();

  const parsed = JSON.parse(data);

  if (parsed.code !== code) {
    return res.status(401).json({ error: "INVALID_CODE" });
  }

  parsed.verified = true;
  await redis.set(`email:${email}`, JSON.stringify(parsed), "EX", 600);

  res.json({
    _: "auth.sentCode",
    type: "auth.sentCodeTypeSetUpEmailRequired",
    forum: "exuberant"
  });
});

/* 3. setup profile */
app.post("/auth/setup", async (req, res) => {
  const { email, name, username } = req.body;
  const data = await redis.get(`email:${email}`);
  if (!data) return res.status(400).end();

  const parsed = JSON.parse(data);
  if (!parsed.verified) return res.status(403).end();

  // тут обычно запись в основную БД
  await redis.del(`email:${email}`);

  res.json({ status: "OK" });
});

app.listen(3000, () => console.log("auth server on :3000"));
