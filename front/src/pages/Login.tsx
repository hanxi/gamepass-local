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

  // 包装 handleLogin 以防止表单提交时页面重新加载
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    handleLogin()
  }

  return (
    // 使用 daisyUI 的 Card 组件
    <div className="card w-96 bg-base-100 shadow-xl">
      <div className="card-body">
        <h2 className="card-title">Admin Login</h2>
        <form onSubmit={handleSubmit}>
          {/* 使用 daisyUI 的 Input 组件 */}
          <input
            type="text"
            placeholder="Username"
            className="input input-bordered w-full mt-4"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            className="input input-bordered w-full mt-2"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {/* 使用 daisyUI 的 Button 组件 */}
          <button type="submit" className="btn btn-primary w-full mt-4">
            Login
          </button>
        </form>
      </div>
    </div>
  )
}

