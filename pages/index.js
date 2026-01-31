import { useState } from "react";

export default function Home() {
  const [step, setStep] = useState("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [msg, setMsg] = useState("");

  async function api(action, data) {
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, ...data }),
    });
    return res.json();
  }

  return (
    <div style={{ maxWidth: 420, margin: "60px auto", fontFamily: "Arial" }}>
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
          <h3>Код из письма</h3>
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
            const r = await api("finish", { email, name, username });
            if (r.ok) setMsg("✅ Готово, аккаунт создан");
            else setMsg(r.error);
          }}>Finish</button>
        </>
      )}

      <p>{msg}</p>
    </div>
  );
}
