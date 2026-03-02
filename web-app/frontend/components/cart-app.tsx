'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';

type AuthResponse = {
  access_token: string;
  token_type: string;
  user: {
    sub: string;
    email: string;
    name: string;
    role: string;
    exp: number;
    iat: number;
  };
};

type UserProfile = {
  id: number;
  email: string;
  name: string;
  role: string;
  address: string;
  phone: string;
  created_at: string;
};

type Product = {
  id: number;
  name: string;
  price: number;
  category: string;
  description: string;
  image: string;
  featured: boolean;
};

type ProductResponse = {
  items: Product[];
};

type CartItem = {
  id: number;
  user_id: string;
  product_name: string;
  quantity: number;
  price: number;
};

type CartResponse = {
  items: CartItem[];
  total: number;
};

type View = 'home' | 'cart' | 'profile';
type AuthMode = 'login' | 'register';

const authApiUrl = process.env.NEXT_PUBLIC_AUTH_API_URL || 'http://localhost:8001';
const cartApiUrl = process.env.NEXT_PUBLIC_CART_API_URL || 'http://localhost:8003';
const productApiUrl = process.env.NEXT_PUBLIC_PRODUCT_API_URL || 'http://localhost:8004';
const storageKey = 'quitty-session';

export function CartApp() {
  const [authMode, setAuthMode] = useState<AuthMode>('login');
  const [view, setView] = useState<View>('home');
  const [status, setStatus] = useState('Sign in to continue.');
  const [token, setToken] = useState('');
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [products, setProducts] = useState<Product[]>([]);
  const [items, setItems] = useState<CartItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [email, setEmail] = useState('alice@example.com');
  const [password, setPassword] = useState('password123');
  const [registerName, setRegisterName] = useState('');
  const [registerEmail, setRegisterEmail] = useState('');
  const [registerPassword, setRegisterPassword] = useState('');
  const [registerAddress, setRegisterAddress] = useState('');
  const [registerPhone, setRegisterPhone] = useState('');

  const isLoggedIn = token.length > 0;
  const cartCount = useMemo(() => items.reduce((sum, item) => sum + item.quantity, 0), [items]);
  const featuredProducts = useMemo(() => products.filter((product) => product.featured), [products]);

  useEffect(() => {
    const saved = window.localStorage.getItem(storageKey);
    if (!saved) {
      return;
    }

    const parsed = JSON.parse(saved) as { token: string };
    void hydrateSession(parsed.token);
  }, []);

  useEffect(() => {
    if (token) {
      window.localStorage.setItem(storageKey, JSON.stringify({ token }));
      return;
    }
    window.localStorage.removeItem(storageKey);
  }, [token]);

  async function hydrateSession(activeToken: string) {
    setToken(activeToken);
    const ok = await loadProfile(activeToken);
    if (!ok) {
      return;
    }
    await Promise.all([loadProducts(), loadCart(activeToken)]);
    setView('home');
    setStatus('Welcome back.');
  }

  async function loadProfile(activeToken: string): Promise<boolean> {
    const response = await fetch(`${authApiUrl}/me`, {
      headers: { Authorization: `Bearer ${activeToken}` }
    });

    if (!response.ok) {
      resetSession();
      setStatus('Your session is no longer valid.');
      return false;
    }

    const data = (await response.json()) as UserProfile;
    setProfile(data);
    return true;
  }

  async function loadProducts() {
    setCatalogLoading(true);
    const response = await fetch(`${productApiUrl}/products`);
    const data = (await response.json()) as ProductResponse;
    setProducts(data.items);
    setCatalogLoading(false);
  }

  async function loadCart(activeToken = token) {
    if (!activeToken) {
      return;
    }
    const response = await fetch(`${cartApiUrl}/cart`, {
      headers: { Authorization: `Bearer ${activeToken}` }
    });
    if (!response.ok) {
      setStatus('Could not load your cart.');
      return;
    }
    const data = (await response.json()) as CartResponse;
    setItems(data.items);
    setTotal(data.total);
  }

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setStatus('Signing in...');

    const response = await fetch(`${authApiUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
      setLoading(false);
      setStatus('Login failed. Check your email and password.');
      return;
    }

    const data = (await response.json()) as AuthResponse;
    await hydrateSession(data.access_token);
    setLoading(false);
  }

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setStatus('Creating your account...');

    const response = await fetch(`${authApiUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: registerName,
        email: registerEmail,
        password: registerPassword,
        address: registerAddress,
        phone: registerPhone
      })
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Registration failed' }));
      setLoading(false);
      setStatus(error.detail || 'Registration failed.');
      return;
    }

    const data = (await response.json()) as AuthResponse;
    await hydrateSession(data.access_token);
    setLoading(false);
    setStatus('Account created successfully.');
  }

  async function addProductToCart(product: Product) {
    const response = await fetch(`${cartApiUrl}/cart`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        product_name: product.name,
        quantity: 1,
        price: product.price
      })
    });

    if (!response.ok) {
      setStatus('Could not add this product to the cart.');
      return;
    }

    await loadCart();
    setView('cart');
    setStatus(`${product.name} added to cart.`);
  }

  async function removeItem(itemId: number) {
    const response = await fetch(`${cartApiUrl}/cart/${itemId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!response.ok) {
      setStatus('Could not remove the item.');
      return;
    }

    await loadCart();
    setStatus('Item removed from cart.');
  }

  function resetSession() {
    setToken('');
    setProfile(null);
    setProducts([]);
    setItems([]);
    setTotal(0);
    setView('home');
  }

  function logout() {
    resetSession();
    setStatus('Signed out.');
    setAuthMode('login');
  }

  if (!isLoggedIn) {
    return (
      <main>
        <section className="auth-shell">
          <div className="auth-card">
            <div className="auth-copy">
              <p className="eyebrow">Quitty</p>
              <h1>{authMode === 'login' ? 'Login to your account' : 'Create your account'}</h1>
              <p className="muted">
                {authMode === 'login'
                  ? 'Only authenticated users can access Home, Cart, and Profile.'
                  : 'Register once, then you will be taken directly into the application.'}
              </p>
            </div>

            <div className="auth-switcher">
              <button className={authMode === 'login' ? 'tab active' : 'tab'} onClick={() => setAuthMode('login')} type="button">Login</button>
              <button className={authMode === 'register' ? 'tab active' : 'tab'} onClick={() => setAuthMode('register')} type="button">Register</button>
            </div>

            {authMode === 'login' ? (
              <form className="form auth-form" onSubmit={login}>
                <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Email" type="email" />
                <input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" />
                <button type="submit" disabled={loading}>{loading ? 'Please wait...' : 'Login'}</button>
              </form>
            ) : (
              <form className="form auth-form" onSubmit={register}>
                <input value={registerName} onChange={(event) => setRegisterName(event.target.value)} placeholder="Full name" required />
                <input value={registerEmail} onChange={(event) => setRegisterEmail(event.target.value)} placeholder="Email" type="email" required />
                <input value={registerPassword} onChange={(event) => setRegisterPassword(event.target.value)} placeholder="Password" type="password" required />
                <input value={registerAddress} onChange={(event) => setRegisterAddress(event.target.value)} placeholder="Address" required />
                <input value={registerPhone} onChange={(event) => setRegisterPhone(event.target.value)} placeholder="Phone number" required />
                <button type="submit" disabled={loading}>{loading ? 'Please wait...' : 'Register'}</button>
              </form>
            )}

            <p className="notice auth-notice">{status}</p>
            <p className="muted demo-copy">Demo login: `alice@example.com` / `password123`</p>
          </div>
        </section>
      </main>
    );
  }

  return (
    <main>
      <section className="shell app-shell">
        <div className="app-header">
          <div>
            <p className="eyebrow">Quitty Dashboard</p>
            <h1>Welcome, {profile?.name}</h1>
            <p className="muted">Move through the application using Home, Cart, and Profile.</p>
          </div>
          <div className="header-meta">
            <span className="pill">{profile?.role}</span>
            <span className="pill">{cartCount} items</span>
          </div>
        </div>

        <div className="nav-bar">
          <div className="nav-tabs">
            <button className={view === 'home' ? 'tab active' : 'tab'} onClick={() => setView('home')} type="button">Home</button>
            <button className={view === 'cart' ? 'tab active' : 'tab'} onClick={() => setView('cart')} type="button">Cart</button>
            <button className={view === 'profile' ? 'tab active' : 'tab'} onClick={() => setView('profile')} type="button">Profile</button>
          </div>
          <button className="secondary" onClick={logout} type="button">Logout</button>
        </div>

        <div className="notice">{status}</div>

        {view === 'home' ? (
          <section className="panel section-panel">
            <div className="section-head">
              <div>
                <h2>Home</h2>
                <p className="muted">Browse products and add them to your cart.</p>
              </div>
            </div>
            <div className="feature-strip">
              {featuredProducts.map((product) => (
                <article className="feature-card" key={product.id}>
                  <span className="pill accent-pill">{product.category}</span>
                  <strong>{product.name}</strong>
                  <p>{product.description}</p>
                  <div className="row between">
                    <span className="price-tag">${product.price.toFixed(2)}</span>
                    <button onClick={() => addProductToCart(product)} type="button">Add to Cart</button>
                  </div>
                </article>
              ))}
            </div>
            <div className="product-grid">
              {catalogLoading ? <p>Loading products...</p> : null}
              {products.map((product) => (
                <article className="product-card" key={product.id}>
                  <div className="product-image" style={{ backgroundImage: `url(${product.image})` }} />
                  <div className="product-body">
                    <div className="row between compact">
                      <span className="pill">{product.category}</span>
                      <span className="price-tag">${product.price.toFixed(2)}</span>
                    </div>
                    <strong>{product.name}</strong>
                    <p>{product.description}</p>
                    <button onClick={() => addProductToCart(product)} type="button">Add to Cart</button>
                  </div>
                </article>
              ))}
            </div>
          </section>
        ) : null}

        {view === 'cart' ? (
          <section className="panel section-panel">
            <div className="section-head">
              <div>
                <h2>Cart</h2>
                <p className="muted">Everything you have added is stored here.</p>
              </div>
              <button className="secondary" onClick={() => loadCart()} type="button">Refresh</button>
            </div>
            <div className="list">
              {items.length === 0 ? <p>Your cart is empty.</p> : null}
              {items.map((item) => (
                <article className="card cart-card" key={item.id}>
                  <div>
                    <strong>{item.product_name}</strong>
                    <p className="muted">Quantity: {item.quantity}</p>
                  </div>
                  <div className="row compact">
                    <span className="price-tag">${item.price.toFixed(2)}</span>
                    <button className="secondary" onClick={() => removeItem(item.id)} type="button">Remove</button>
                  </div>
                </article>
              ))}
            </div>
            <div className="checkout-bar">
              <span>Total</span>
              <strong>${total.toFixed(2)}</strong>
            </div>
          </section>
        ) : null}

        {view === 'profile' ? (
          <section className="panel section-panel">
            <div className="section-head">
              <div>
                <h2>Profile</h2>
                <p className="muted">Your registered account information.</p>
              </div>
            </div>
            <div className="profile-grid">
              <article className="profile-card">
                <span className="profile-label">Name</span>
                <strong>{profile?.name}</strong>
              </article>
              <article className="profile-card">
                <span className="profile-label">Email</span>
                <strong>{profile?.email}</strong>
              </article>
              <article className="profile-card">
                <span className="profile-label">Role</span>
                <strong>{profile?.role}</strong>
              </article>
              <article className="profile-card wide">
                <span className="profile-label">Address</span>
                <strong>{profile?.address}</strong>
              </article>
              <article className="profile-card wide">
                <span className="profile-label">Phone</span>
                <strong>{profile?.phone}</strong>
              </article>
            </div>
          </section>
        ) : null}
      </section>
    </main>
  );
}
