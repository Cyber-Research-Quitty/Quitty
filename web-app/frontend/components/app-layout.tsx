'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { ReactNode } from 'react';

import { UserProfile } from './types';
import { clearStoredToken } from '../lib/session';

type Props = {
  children: ReactNode;
  current: 'home' | 'cart' | 'profile';
  profile: UserProfile;
  cartCount?: number;
  status?: string;
};

const navItems = [
  { href: '/home', label: 'Home', key: 'home', icon: '⌂' },
  { href: '/cart', label: 'Cart', key: 'cart', icon: '🛒' },
  { href: '/profile', label: 'Profile', key: 'profile', icon: '◉' }
] as const;

const extraItems = [
  { label: 'Orders', icon: '↺' },
  { label: 'Security', icon: '🛡' }
] as const;

export function AppLayout({ children, current, profile, cartCount = 0, status = '' }: Props) {
  const router = useRouter();
  const pathname = usePathname();

  function logout() {
    clearStoredToken();
    router.replace('/');
    router.refresh();
  }

  return (
    <main>
      <section className="app-frame">
        <aside className="app-sidebar">
          <div className="sidebar-brand">
            <div className="brand-icon">⬢</div>
            <div>
              <strong>Quantum Shield</strong>
              <p>Secure Commerce</p>
            </div>
          </div>

          <nav className="sidebar-nav" aria-label="Primary navigation">
            {navItems.map((item) => (
              <Link
                key={item.href}
                className={current === item.key || pathname === item.href ? 'nav-item active' : 'nav-item'}
                href={item.href}
              >
                <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                <span>{item.label}</span>
                {item.key === 'cart' && cartCount > 0 ? <span className="nav-count">{cartCount}</span> : null}
              </Link>
            ))}
          </nav>

          <div className="sidebar-section">
            {extraItems.map((item) => (
              <div className="ghost-item" key={item.label}>
                <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                <span>{item.label}</span>
              </div>
            ))}
          </div>

          <div className="sidebar-footer">
            <div className="user-chip">
              <div className="user-initial">{profile.name.charAt(0).toUpperCase()}</div>
              <div>
                <strong>{profile.name}</strong>
                <p>Member Since {new Date(profile.created_at).getFullYear()}</p>
              </div>
            </div>
            <button className="ghost-button" onClick={logout} type="button">Sign Out</button>
          </div>
        </aside>

        <div className="app-shell">
          <header className="utility-bar">
            <div className="utility-brand">
              <div className="brand-mark">⬢</div>
              <strong>Quantum Shield Commerce</strong>
            </div>
            <div className="utility-actions">
              <label className="search-box">
                <span aria-hidden="true">⌕</span>
                <input placeholder="Search secure products..." />
              </label>
              <div className="utility-icon cart-indicator">
                <span aria-hidden="true">🛒</span>
                {cartCount > 0 ? <b>{cartCount}</b> : null}
              </div>
              <div className="utility-icon" aria-hidden="true">👤</div>
            </div>
          </header>

          {status ? <div className="page-note">{status}</div> : null}
          <div className="page-content">{children}</div>
        </div>
      </section>
    </main>
  );
}
