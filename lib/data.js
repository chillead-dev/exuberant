import { v4 as uuid } from "uuid"

export const users = new Map()
export const chats = new Map()

export function getOrCreateChat(a, b) {
  const key = [a, b].sort().join(":")
  if (!chats.has(key)) {
    chats.set(key, {
      id: key,
      users: [a, b],
      messages: [],
      pinned: null
    })
  }
  return chats.get(key)
}

export function addMessage(chatId, msg) {
  const chat = chats.get(chatId)
  if (!chat) return null

  const message = {
    id: uuid(),
    ...msg,
    createdAt: Date.now(),
    edited: false
  }

  chat.messages.push(message)
  return message
}
