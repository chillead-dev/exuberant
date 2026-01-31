"use client";
import { useState } from "react";

export default function Page() {
  const [step, setStep] = useState<"signup" | "code" | "profile">("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [msg, setMsg] = useState("");

  async function api(action: string, body: any) {
    const r = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, ...body }),
    });
    return r.json();
  }

  return (
    <main style={{ maxWidth: 420, margin: "50px auto", fontFamily: "sans-serif" }}>
      <h1>Exuberant</h1>

      {step === "signup" && (
        <>
          <h3>Регистрация</h3>
          <input placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
          <input placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
          <button onClick={async () => {
            setMsg("Отправка кода...");
            const r = await api("send_code", { email, password });
            if (r.ok) setStep("code");
            else setMsg(r.error);
          }}>Send code</button>
        </>
      )}

      {step === "code" && (
        <>
          <h3>Введите код</h3>
          <input placeholder="6-digit code" value={code} onChange={e => setCode(e.target.value)} />
          <button onClick={async () => {
            setMsg("Проверка...");
            const r = await api("verify_code", { email, code });
            if (r.ok) setStep("profile");
            else setMsg(r.error);
          }}>Verify</button>
        </>
      )}

      {step === "profile" && (
        <>
          <h3>Профиль</h3>
          <input placeholder="name" value={name} onChange={e => setName(e.target.value)} />
          <input placeholder="@username" value={username} onChange={e => setUsername(e.target.value)} />
          <button onClick={async () => {
            setMsg("Сохранение...");
            const r = await api("finish", { name, username });
            if (r.ok) setMsg("✅ Готово, аккаунт создан");
            else setMsg(r.error);
          }}>Finish</button>
        </>
      )}

      <p>{msg}</p>
    </main>
  );
}
