import React, { useState } from 'react';

export default function Login({ onSuccess, onRegister }: {onSuccess: (isAdmin: boolean) => void; onRegister: () => void}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);

  const handleLogin = async () => {
    console.log('Starting login process...');
    let endpoint;
    if (isAdmin) {
      console.log('Using admin login endpoint.');
      endpoint = '/api/admin/login';
    } else {
      console.log('Using regular login endpoint.');
      endpoint = '/api/auth/login';
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (res.ok) {
      if (isAdmin) {
        console.log('Admin login successful.');
        setIsAdmin(true);
        onSuccess(isAdmin);
      } else {
        console.log('Regular login successful.');
        onSuccess(isAdmin);
      }
    } else {
      console.log('Login failed.');
      alert('Login failed');
    }
  };

  // 包装 handleLogin 以防止表单提交时页面重新加载
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleLogin();
  };

  return (
    // 使用 daisyUI 的 Card 组件
    <div className="flex justify-center items-center h-screen">
      <div className="card w-96 bg-base-100 shadow-xl">
        <div className="card-body flex flex-col items-center">
          <div className="flex justify-center items-center">
            <h2 className="card-title">Login</h2>
          </div>
          <form onSubmit={handleSubmit}>
            {/* 使用 daisyUI 的 Input 组件 */}
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
            {/* 优化复选框样式 */}
            <div className="flex justify-center items-center mt-4">
              <label className="label cursor-pointer">
                <span className="label-text">Admin Login</span>
                <input type="checkbox" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} className="toggle toggle-lg" />
              </label>
            </div>
            {/* 使用 daisyUI 的 Button 组件 */}
            <button type="submit" className="btn btn-primary w-full mt-4">
              Login
            </button>
          </form>
          {/* 新增注册链接 */}
          <p className="mt-4 text-center">
            Don't have an account?
            <span onClick={onRegister} className="text-blue-500 cursor-pointer underline ml-1">
              Register here
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}