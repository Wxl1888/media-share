import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import '../styles/Auth.css';

function Auth() {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const navigate = useNavigate();

  const handleAuth = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      if (isLogin) {
        // 登录
        if (!email || !password) {
          setMessage('请填写所有字段');
          setMessageType('error');
          return;
        }

        const response = await axios.post('/api/auth/login', {
          email,
          password
        });

        localStorage.setItem('token', response.data.token);
        localStorage.setItem('user', JSON.stringify(response.data.user));
        setMessage('登录成功！');
        setMessageType('success');
        setTimeout(() => navigate('/dashboard'), 1000);
      } else {
        // 注册
        if (!username || !email || !password || !confirmPassword) {
          setMessage('请填写所有字段');
          setMessageType('error');
          return;
        }

        if (password !== confirmPassword) {
          setMessage('两次输入的密码不一致');
          setMessageType('error');
          return;
        }

        if (password.length < 6) {
          setMessage('密码至少需要 6 个字符');
          setMessageType('error');
          return;
        }

        const response = await axios.post('/api/auth/register', {
          username,
          email,
          password
        });

        localStorage.setItem('token', response.data.token);
        localStorage.setItem('user', JSON.stringify(response.data.user));
        setMessage('注册成功！');
        setMessageType('success');
        setTimeout(() => navigate('/dashboard'), 1000);
      }
    } catch (error) {
      setMessage(error.response?.data?.error || '操作失败');
      setMessageType('error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-card">
          <h1>{isLogin ? '🔓 登录' : '📝 注册'}</h1>
          <p className="auth-subtitle">
            {isLogin ? '登录您的账户' : '创建新账户'}
          </p>

          <form onSubmit={handleAuth}>
            {!isLogin && (
              <div className="form-group">
                <label>用户名</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="输入用户名"
                  required
                />
              </div>
            )}

            <div className="form-group">
              <label>邮箱</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="输入邮箱"
                required
              />
            </div>

            <div className="form-group">
              <label>密码</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="输入密码"
                required
              />
            </div>

            {!isLogin && (
              <div className="form-group">
                <label>确认密码</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="再次输入密码"
                  required
                />
              </div>
            )}

            {message && (
              <div className={`message ${messageType}`}>
                {message}
              </div>
            )}

            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? '处理中...' : (isLogin ? '登录' : '注册')}
            </button>
          </form>

          <div className="auth-toggle">
            {isLogin ? '还没有账户？' : '已有账户？'}
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setMessage('');
              }}
              className="toggle-btn"
            >
              {isLogin ? '立即注册' : '返回登录'}
            </button>
          </div>
        </div>

        <div className="auth-info">
          <h2>🚀 开始使用</h2>
          <ul>
            <li>✅ 安全的媒体分享</li>
            <li>✅ 密码保护分享</li>
            <li>✅ 自动过期管理</li>
            <li>✅ 详细的使用统计</li>
            <li>✅ 全球时区显示</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default Auth;
