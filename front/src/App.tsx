import React, { useState } from 'react'
import Login from './pages/Login'
import Admin from './pages/Admin'

export default function App() {
  const [page, setPage] = useState<'login' | 'admin'>('login')

  return (
    <div className="min-h-screen bg-base-200">
      {page === 'login' && <Login onSuccess={() => setPage('admin')} />}
      {page === 'admin' && <Admin onLogout={() => setPage('login')} />}
    </div>
  )
}

