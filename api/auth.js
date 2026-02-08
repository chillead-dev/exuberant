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

function readBody(req) {
  return new Promise((resolve) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => resolve(d ? JSON.parse(d) : {}));
  });
}

function json(res, code, data) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(data));
}

function setCookie(res, email) {
  res.setHeader(
    "Set-Cookie",
    `session=${email}; Path=/; HttpOnly; SameSite=Lax`
  );
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { ok: false });
  }

  const body = await readBody(req);
  const { action } = body;

  /* ================= REGISTRATION ================= */

  if (action === "register") {
    const { email, password, name, username } = body;

    if (!email || !password || !username) {
      return json(res, 400, { ok: false, error: "missing_fields" });
    }

    const exists = await redis("get", `user:${email}`);
    if (exists.result) {
      return json(res, 409, { ok: false, error: "user_exists" });
    }

    const unameTaken = await redis("get", `username:${username}`);
    if (unameTaken.result) {
      return json(res, 409, { ok: false, error: "username_taken" });
    }

    const user = {
      email,
      password, // ⚠️ пока без хеша (потом добавим)
      name: name || "",
      username,
      avatar: "",
      badges: email === ADMIN_EMAIL ? ["developer"] : [],
      created: Date.now(),
    };

    await redis("set", `user:${email}`, JSON.stringify(user));
    await redis("set", `username:${username}`, email);

    setCookie(res, email);
    return json(res, 200, { ok: true });
  }

  /* ================= LOGIN ================= */

  if (action === "login") {
    const { email, password } = body;

    const r = await redis("get", `user:${email}`);
    if (!r.result) {
      return json(res, 401, { ok: false });
    }

    const user = JSON.parse(r.result);
    if (user.password !== password) {
      return json(res, 401, { ok: false });
    }

    setCookie(res, email);
    return json(res, 200, { ok: true });
  }

  /* ================= LOGOUT ================= */

  if (action === "logout") {
    res.setHeader(
      "Set-Cookie",
      "session=; Path=/; Max-Age=0; HttpOnly"
    );
    return json(res, 200, { ok: true });
  }

  return json(res, 400, { ok: false });
}
