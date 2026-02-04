import { verifyToken } from "@/lib/auth"
import { getOrCreateChat, addMessage } from "@/lib/data"

export default function handler(req, res) {
  const user = verifyToken(req)
  if (!user) return res.status(401).end()

  if (req.method === "POST") {
    const { to, text } = req.body
    const chat = getOrCreateChat(user.id, to)

    const msg = addMessage(chat.id, {
      from: user.id,
      text
    })

    return res.json({ chat, msg })
  }

  if (req.method === "GET") {
    const { withUser } = req.query
    const chat = getOrCreateChat(user.id, withUser)
    return res.json(chat)
  }
}
