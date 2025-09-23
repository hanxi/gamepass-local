import React from 'react'
import { useState } from 'react'
import Login from './pages/Login'
import Admin from './pages/Admin'

export default function App() {
  const [page, setPage] = useState<'login' | 'admin'>('login')
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      {page === 'login' && <Login onSuccess={() => setPage('admin')} />}
      {page === 'admin' && <Admin />}
    </div>
  )
}
