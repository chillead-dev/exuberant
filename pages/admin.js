import { verifyToken, isAdmin } from "@/lib/auth"

export default function Admin({ user }) {
  if (!user || !user.isAdmin) return <h1>403</h1>

  return (
    <div>
      <h1>Admin Panel</h1>
      <button>Ban user</button>
      <button>Give badge</button>
    </div>
  )
}

export async function getServerSideProps({ req }) {
  const user = verifyToken(req)
  return { props: { user } }
}
