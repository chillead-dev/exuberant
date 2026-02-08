const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

async function redis(command, ...args) {
  const r = await fetch(REDIS_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${REDIS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ command, args }),
  });
  return r.json();
}

function json(res, code, data) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(data));
}

function getCookies(req) {
  const out = {};
  (req.headers.cookie || "")
    .split(";")
    .forEach((p) => {
      const [k, v] = p.trim().split("=");
      if (k) out[k] = v;
    });
  return out;
}

function makeThreadId(a, b) {
  return [a, b].sort().join("::");
}

export default async function handler(req, res) {
  const cookies = getCookies(req);
  const email = cookies.session;

  if (!email) {
    return json(res, 401, { ok: false });
  }

  const userRaw = await redis("get", `user:${email}`);
  if (!userRaw.result) {
    return json(res, 401, { ok: false });
  }

  const user = JSON.parse(userRaw.result);

  /* ================= PROFILE ================= */

  if (req.query.action === "me") {
    return json(res, 200, { ok: true, user });
  }

  if (req.query.action === "user") {
    const u = req.query.u;
    const email2 = (await redis("get", `username:${u}`)).result;
    if (!email2) return json(res, 404, { ok: false });

    const u2 = JSON.parse((await redis("get", `user:${email2}`)).result);
    return json(res, 200, { ok: true, user: u2 });
  }

  /* ================= CHATS ================= */

  if (req.query.action === "chat_init") {
    const peerUsername = req.query.u;
    const peerEmail = (await redis("get", `username:${peerUsername}`)).result;
    if (!peerEmail) return json(res, 404, { ok: false });

    const threadId = makeThreadId(email, peerEmail);

    await redis("sadd", `chats:${email}`, threadId);
    await redis("sadd", `chats:${peerEmail}`, threadId);

    return json(res, 200, { ok: true, threadId });
  }

  if (req.query.action === "chat_list") {
    const r = await redis("smembers", `chats:${email}`);
    const chats = [];

    for (const tid of r.result || []) {
      const [a, b] = tid.split("::");
      const peerEmail = a === email ? b : a;
      const peer = JSON.parse((await redis("get", `user:${peerEmail}`)).result);

      chats.push({
        threadId: tid,
        peer: {
          username: peer.username,
          name: peer.name,
          avatar: peer.avatar,
          badges: peer.badges,
        },
      });
    }

    return json(res, 200, { ok: true, chats });
  }

  if (req.query.action === "chat_send" && req.method === "POST") {
    let body = "";
    for await (const c of req) body += c;
    body = JSON.parse(body || "{}");

    const msg = {
      id: Date.now(),
      from: email,
      text: body.text,
      ts: Date.now(),
    };

    await redis(
      "rpush",
      `chat:${body.threadId}:msgs`,
      JSON.stringify(msg)
    );

    return json(res, 200, { ok: true });
  }

  if (req.query.action === "chat_fetch") {
    const r = await redis(
      "lrange",
      `chat:${req.query.threadId}:msgs`,
      0,
      -1
    );
    const msgs = (r.result || []).map(JSON.parse);
    return json(res, 200, { ok: true, messages: msgs });
  }

  return json(res, 400, { ok: false });
}
