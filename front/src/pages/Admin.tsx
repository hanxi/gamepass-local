import React, { useEffect, useState } from 'react'

interface User {
  username: string
}

export default function Admin() {
  const [users, setUsers] = useState<User[]>([])

  useEffect(() => {
    fetch('/api/admin/users').then(res => res.json()).then(setUsers)
  }, [])

  return (
    <div className="p-6 bg-white rounded shadow-md w-full max-w-lg">
      <h2 className="text-xl mb-4">User List</h2>
      <ul>
        {users.map((u, i) => (
          <li key={i} className="border-b py-1">{u.username}</li>
        ))}
      </ul>
    </div>
  )
}
