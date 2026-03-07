'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';

import { AppLayout } from './app-layout';
import { CartItem, CartResponse, UserProfile } from './types';
import { authApiUrl, cartApiUrl, clearStoredToken, getStoredToken } from '../lib/session';

export function CartPage() {
  const router = useRouter();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [items, setItems] = useState<CartItem[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState('Secure your digital assets. All transactions are quantum-encrypted.');

  useEffect(() => {
    void loadPage();
  }, []);

  async function loadPage() {
    const token = getStoredToken();
    if (!token) {
      router.replace('/');
      return;
    }

    const profileResponse = await fetch(`${authApiUrl}/me`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!profileResponse.ok) {
      clearStoredToken();
      router.replace('/');
      return;
    }
    setProfile((await profileResponse.json()) as UserProfile);

    await loadCart(token);
  }

  async function loadCart(token: string) {
    const response = await fetch(`${cartApiUrl}/cart`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      setStatus('Could not load protected cart.');
      return;
    }
    const data = (await response.json()) as CartResponse;
    setItems(data.items);
    setTotal(data.total);
  }

  async function removeItem(itemId: number) {
    const token = getStoredToken();
    const response = await fetch(`${cartApiUrl}/cart/${itemId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      setStatus('Could not remove the item.');
      return;
    }
    await loadCart(token);
    setStatus('Item removed from secure cart.');
  }

  const cartCount = useMemo(() => items.reduce((sum, item) => sum + item.quantity, 0), [items]);
  const shipping = items.length > 0 ? 12 : 0;

  if (!profile) {
    return null;
  }

  return (
    <AppLayout current="cart" profile={profile} cartCount={cartCount} status={status}>
      <section className="page-hero compact-hero">
        <h1>Protected Storefront - Cart</h1>
        <p>Secure your digital assets. All transactions are quantum-encrypted.</p>
      </section>

      <section className="cart-grid-modern">
        <div className="cart-lines">
          {items.length === 0 ? <p>Your secure cart is empty.</p> : null}
          {items.map((item) => (
            <article className="cart-modern-card" key={item.id}>
              <div className="cart-modern-image" />
              <div className="cart-modern-main">
                <strong>{item.product_name}</strong>
                <p>{item.quantity > 1 ? `${item.quantity} protected units` : 'Premium secured item'}</p>
                <div className="qty-shell">
                  <button disabled type="button">-</button>
                  <span>{item.quantity}</span>
                  <button disabled type="button">+</button>
                </div>
              </div>
              <div className="cart-modern-side">
                <span className="cart-price">${(item.price * item.quantity).toFixed(2)}</span>
                <button className="link-button muted-link" onClick={() => removeItem(item.id)} type="button">Remove</button>
              </div>
            </article>
          ))}
        </div>

        <aside className="order-summary-card">
          <h3>Order Summary</h3>
          <div className="summary-row"><span>Items count</span><strong>{cartCount}</strong></div>
          <div className="summary-row"><span>Estimated Shipping</span><strong>${shipping.toFixed(2)}</strong></div>
          <div className="summary-row"><span>Tax estimate</span><strong>Included</strong></div>
          <div className="summary-row total-row"><span>Total</span><strong>${(total + shipping).toFixed(2)}</strong></div>
          <button className="primary-cta" type="button">Proceed to Checkout</button>
          <p className="summary-note">Secure checkout by Quantum Shield</p>
          <div className="discount-box">
            <span>Discount Code</span>
            <div className="discount-row">
              <input defaultValue="SHIELD20" readOnly />
              <button className="apply-button" type="button">Apply</button>
            </div>
          </div>
        </aside>
      </section>

      <footer className="commerce-footer">
        <div>
          <strong>Quantum Shield Commerce</strong>
          <p>The world&apos;s secure digital marketplace with next-generation encrypted transactions.</p>
        </div>
        <div>
          <strong>Shop</strong>
          <p>Featured Items</p>
          <p>New Arrivals</p>
          <p>Hardware</p>
        </div>
        <div>
          <strong>Support</strong>
          <p>Help Center</p>
          <p>Secure Delivery</p>
          <p>Returns</p>
        </div>
        <div>
          <strong>Trust</strong>
          <p>SSL Secure</p>
          <p>Quantum Proof</p>
        </div>
      </footer>
    </AppLayout>
  );
}
