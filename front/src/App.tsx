import React, { useState } from 'react'
import Login from './pages/Login'
import Admin from './pages/Admin'
import Register from './pages/Register'
import UserWelcome from './pages/UserWelcome'

export default function App() {
  const [page, setPage] = useState<'login' | 'admin' | 'register' | 'userwelcome'>('login')

  return (
    <div className="min-h-screen bg-base-200">
      {page === 'login' && <Login onSuccess={() => setPage(isAdmin ? 'admin' : 'userwelcome')} onRegister={() => setPage('register')} />}
      {page === 'admin' && <Admin onLogout={() => setPage('login')} />}
      {page === 'register' && <Register onSuccess={() => setPage('login')} />}
      {page === 'userwelcome' && <UserWelcome />}
    </div>
  )
}