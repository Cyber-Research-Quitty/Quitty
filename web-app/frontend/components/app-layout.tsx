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
  { href: '/home', label: 'Home', key: 'home', icon: 'home' },
  { href: '/cart', label: 'Cart', key: 'cart', icon: 'cart' },
  { href: '/profile', label: 'Profile', key: 'profile', icon: 'profile' }
] as const;

const extraItems = [
  { label: 'Orders', icon: 'orders' },
  { label: 'Security', icon: 'shield' }
] as const;

type IconName = 'home' | 'cart' | 'profile' | 'orders' | 'shield' | 'search';

function Icon({ name }: { name: IconName }) {
  switch (name) {
    case 'home':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M3 10.5L12 3l9 7.5" />
          <path d="M5 9.5V21h14V9.5" />
          <path d="M10 21v-6h4v6" />
        </svg>
      );
    case 'cart':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="9" cy="20" r="1.5" />
          <circle cx="18" cy="20" r="1.5" />
          <path d="M3 4h2l2.6 10.2a1 1 0 0 0 1 .8h8.9a1 1 0 0 0 1-.7L21 7H7" />
        </svg>
      );
    case 'profile':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="8" r="4" />
          <path d="M4 20c1.8-3.2 4.5-4.8 8-4.8s6.2 1.6 8 4.8" />
        </svg>
      );
    case 'orders':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M3 12a9 9 0 1 0 3-6.7" />
          <path d="M3 3v6h6" />
          <path d="M12 7v5l3 2" />
        </svg>
      );
    case 'shield':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 3l7 3v6c0 4.7-2.9 7.9-7 9-4.1-1.1-7-4.3-7-9V6l7-3Z" />
        </svg>
      );
    case 'search':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="7" />
          <path d="m20 20-3.5-3.5" />
        </svg>
      );
  }
}

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
                <span className="nav-icon" aria-hidden="true"><Icon name={item.icon} /></span>
                <span>{item.label}</span>
                {item.key === 'cart' && cartCount > 0 ? <span className="nav-count">{cartCount}</span> : null}
              </Link>
            ))}
          </nav>

          <div className="sidebar-section">
            {extraItems.map((item) => (
              <div className="ghost-item" key={item.label}>
                <span className="nav-icon" aria-hidden="true"><Icon name={item.icon} /></span>
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
                <span className="search-icon" aria-hidden="true"><Icon name="search" /></span>
                <input placeholder="Search secure products..." />
              </label>
              <div className="utility-icon cart-indicator">
                <span className="utility-svg" aria-hidden="true"><Icon name="cart" /></span>
                {cartCount > 0 ? <b>{cartCount}</b> : null}
              </div>
              <div className="utility-icon" aria-hidden="true">
                <span className="utility-svg"><Icon name="profile" /></span>
              </div>
            </div>
          </header>

          {status ? <div className="page-note">{status}</div> : null}
          <div className="page-content">{children}</div>
        </div>
      </section>
    </main>
  );
}
