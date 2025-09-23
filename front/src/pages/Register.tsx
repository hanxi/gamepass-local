import React, { useState } from 'react';

export default function Register({ onSuccess }: {onSuccess: () => void}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleRegister = async () => {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (res.ok) {
      onSuccess();
    } else {
      alert('Registration failed');
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleRegister();
  };

  return (
    <div className="flex justify-center items-center h-screen">
      <div className="card w-96 bg-base-100 shadow-xl">
        <div className="card-body">
          <div className="flex justify-center items-center">
            <h2 className="card-title">Register</h2>
          </div>
          <form onSubmit={handleSubmit}>
            <input
              type="text"
              placeholder="Username"
              className="input input-bordered w-full mt-4 mb-4"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              className="input input-bordered w-full mt-2 mb-4"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit" className="btn btn-primary w-full mt-4">
              Register
            </button>
          </form>
          {/* 新增返回登录页面的链接 */}
          <p className="mt-4 text-center">
            Already have an account?
            <span onClick={() => onSuccess()} className="text-blue-500 cursor-pointer underline ml-1">
              Login here
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}