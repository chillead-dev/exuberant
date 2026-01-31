"use client";
import { useState } from "react";

export default function Page() {
  const [step, setStep] = useState("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [msg, setMsg] = useState("");

  async function call(action, data) {
    const r = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, ...data }),
    });
    return r.json();
  }

  return (
    <main style={{ maxWidth: 400, margin: "50px auto", fontFamily: "Arial" }}>
      <h1>Exuberant</h1>

      {step === "signup" && (
        <>
          <input placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
          <input placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
          <button onClick={async () => {
            setMsg("sending code...");
            const r = await call("send_code", { email, password });
            if (r.ok) setStep("code");
            else setMsg(r.error);
          }}>Send code</button>
        </>
      )}

      {step === "code" && (
        <>
          <input placeholder="code" value={code} onChange={e => setCode(e.target.value)} />
          <button onClick={async () => {
            setMsg("verifying...");
            const r = await call("verify_code", { email, code });
            if (r.ok) setStep("profile");
            else setMsg(r.error);
          }}>Verify</button>
        </>
      )}

      {step === "profile" && (
        <>
          <input placeholder="name" value={name} onChange={e => setName(e.target.value)} />
          <input placeholder="@username" value={username} onChange={e => setUsername(e.target.value)} />
          <button onClick={async () => {
            setMsg("saving...");
            const r = await call("finish", { email, name, username });
            if (r.ok) setMsg("DONE");
            else setMsg(r.error);
          }}>Finish</button>
        </>
      )}

      <p>{msg}</p>
    </main>
  );
}
