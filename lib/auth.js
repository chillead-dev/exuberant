import jwt from "jsonwebtoken"

const SECRET = process.env.JWT_SECRET
const ADMIN_EMAIL = process.env.ADMIN_EMAIL

export function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      isAdmin: user.email === ADMIN_EMAIL,
      verified: true
    },
    SECRET,
    { expiresIn: "30d" }
  )
}

export function verifyToken(req) {
  const token = req.headers.authorization?.split(" ")[1]
  if (!token) return null
  try {
    return jwt.verify(token, SECRET)
  } catch {
    return null
  }
}

export function isAdmin(user) {
  return user?.email === ADMIN_EMAIL
}
