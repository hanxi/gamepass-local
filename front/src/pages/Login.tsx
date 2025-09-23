import React, { useState } from 'react'

export default function Login({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const handleLogin = async () => {
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (res.ok) {
      onSuccess()
    } else {
      alert('Login failed')
    }
  }

  return (
    <div className="p-6 bg-white rounded shadow-md w-80">
      <h2 className="text-xl mb-4">Admin Login</h2>
      <input className="border w-full p-2 mb-2" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
      <input className="border w-full p-2 mb-2" placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button onClick={handleLogin} className="bg-blue-500 text-white px-4 py-2 rounded w-full">Login</button>
    </div>
  )
}
