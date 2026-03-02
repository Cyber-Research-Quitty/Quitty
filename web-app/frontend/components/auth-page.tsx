'use client';

import { FormEvent, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

import { AuthResponse } from './types';
import { authApiUrl, getStoredToken, persistToken } from '../lib/session';

type AuthMode = 'login' | 'register';

export function AuthPage() {
  const router = useRouter();
  const [mode, setMode] = useState<AuthMode>('login');
  const [status, setStatus] = useState('Access your secure commerce dashboard.');
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [registerEmail, setRegisterEmail] = useState('');
  const [registerPassword, setRegisterPassword] = useState('');
  const [address, setAddress] = useState('');
  const [phone, setPhone] = useState('');

  useEffect(() => {
    if (getStoredToken()) {
      router.replace('/home');
    }
  }, [router]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setStatus('Initializing secure login...');

    const response = await fetch(`${authApiUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
      setLoading(false);
      setStatus('Secure access failed. Verify your credentials.');
      return;
    }

    const data = (await response.json()) as AuthResponse;
    persistToken(data.access_token);
    setLoading(false);
    router.replace('/home');
    router.refresh();
  }

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setStatus('Provisioning your secure account...');

    const response = await fetch(`${authApiUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        email: registerEmail,
        password: registerPassword,
        address,
        phone
      })
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Registration failed.' }));
      setLoading(false);
      setStatus(error.detail || 'Registration failed.');
      return;
    }

    await response.json() as AuthResponse;
    setLoading(false);
    setMode('login');
    setEmail(registerEmail);
    setPassword('');
    setName('');
    setRegisterEmail('');
    setRegisterPassword('');
    setAddress('');
    setPhone('');
    setStatus('Registration complete. Sign in with your new account.');
  }

  return (
    <main>
      <section className="auth-layout">
        <div className="auth-promo">
          <div className="promo-brand">
            <div className="brand-mark large">⬢</div>
            <strong>Quantum Shield Commerce</strong>
          </div>

          <div className="promo-main">
            <h1 className="display-title">Inductry First, Quantom Safe E-Commerce Experience.</h1>

            <div className="security-points">
              <article>
                <strong>Security Layer</strong>
                <p>PQC readiness protects sessions and assets against future computational threats.</p>
              </article>
              <article>
                <strong>Access Control</strong>
                <p>Protected entry points and resilient authentication flows for public deployment.</p>
              </article>
              <article>
                <strong>Operations</strong>
                <p>Trusted commerce management with secure profiles, carts, and customer identity flows.</p>
              </article>
            </div>
          </div>

          <div className="promo-footer">
            <span>Fintech Standard 4.0</span>
            <span>ISO/IEC 27001</span>
            <span>NIST PQC Standards</span>
          </div>
        </div>

          <div className="auth-panel">
          <div className="auth-panel-inner">
            <div className="auth-header-block">
              <h2>Welcome to the Shield</h2>
              <p>{status}</p>
            </div>

            <div className="auth-tabs">
              <button className={mode === 'login' ? 'auth-tab active' : 'auth-tab'} onClick={() => setMode('login')} type="button">Login</button>
              <button className={mode === 'register' ? 'auth-tab active' : 'auth-tab'} onClick={() => setMode('register')} type="button">Register</button>
            </div>

            {mode === 'login' ? (
              <form className="auth-form refined-form" onSubmit={login}>
                <label>
                  <span>Secure Email</span>
                  <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="operator@quantumshield.com" type="email" required />
                </label>
                <label>
                  <span>Access Key</span>
                  <input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your secure password" type="password" required />
                </label>
                <div className="remember-row">
                  <label className="remember-box">
                    <input type="checkbox" />
                    <span>Remember this secure device</span>
                  </label>
                  <button className="text-button" type="button">Forgot?</button>
                </div>
                <button className="primary-cta" type="submit" disabled={loading}>
                  {loading ? 'Initializing...' : 'Initialize Secure Login'}
                </button>
              </form>
            ) : (
              <form className="auth-form refined-form" onSubmit={register}>
                <label>
                  <span>Full Name</span>
                  <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Operator name" required />
                </label>
                <label>
                  <span>Secure Email</span>
                  <input value={registerEmail} onChange={(event) => setRegisterEmail(event.target.value)} placeholder="name@quantumshield.com" type="email" required />
                </label>
                <label>
                  <span>Access Key</span>
                  <input value={registerPassword} onChange={(event) => setRegisterPassword(event.target.value)} placeholder="Minimum 8 characters" type="password" required />
                </label>
                <label>
                  <span>Shipping Address</span>
                  <input value={address} onChange={(event) => setAddress(event.target.value)} placeholder="Secure delivery address" required />
                </label>
                <label>
                  <span>Phone Number</span>
                  <input value={phone} onChange={(event) => setPhone(event.target.value)} placeholder="+1 555 000 0000" required />
                </label>
                <button className="primary-cta" type="submit" disabled={loading}>
                  {loading ? 'Provisioning...' : 'Create Secure Account'}
                </button>
              </form>
            )}

            <div className="auth-assurance">End-to-end encrypted session</div>
          </div>
        </div>
      </section>
    </main>
  );
}
