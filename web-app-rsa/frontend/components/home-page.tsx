'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';

import { AppLayout } from './app-layout';
import { CartResponse, Product, ProductResponse, UserProfile } from './types';
import { authApiUrl, authHeaders, cartApiUrl, clearStoredToken, getStoredToken, productApiUrl } from '../lib/session';

export function HomePage() {
  const router = useRouter();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [products, setProducts] = useState<Product[]>([]);
  const [cartCount, setCartCount] = useState(0);
  const [status, setStatus] = useState('Protected storefront active. Inventory is ready for secure trade.');

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

    const [productResponse, cartResponse] = await Promise.all([
      fetch(`${productApiUrl}/products`),
      fetch(`${cartApiUrl}/cart`, { headers: { Authorization: `Bearer ${token}` } })
    ]);

    setProducts(((await productResponse.json()) as ProductResponse).items);

    if (cartResponse.ok) {
      const cartData = (await cartResponse.json()) as CartResponse;
      setCartCount(cartData.items.reduce((sum, item) => sum + item.quantity, 0));
    }
  }

  async function addProductToCart(product: Product) {
    const token = getStoredToken();
    const response = await fetch(`${cartApiUrl}/cart`, {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify({
        product_name: product.name,
        quantity: 1,
        price: product.price
      })
    });

    if (!response.ok) {
      setStatus('Unable to add the product to the protected cart.');
      return;
    }

    setCartCount((current) => current + 1);
    setStatus(`${product.name} secured in cart.`);
    router.push('/cart');
  }

  const featuredProducts = useMemo(() => products.filter((product) => product.featured).slice(0, 3), [products]);
  const categories = Array.from(new Set(products.map((product) => product.category)));

  if (!profile) {
    return null;
  }

  return (
    <AppLayout current="home" profile={profile} cartCount={cartCount} status={status}>
      <section className="hero-card home-hero-card">
        <div className="hero-copy-block">
          <span className="badge-label">Secured Platform</span>
          <h1 className="hero-title">Quantum-Safe Marketplace</h1>
          <p className="hero-subtitle">
            Trade through a storefront positioned for high-trust, attack-resilient digital commerce. Protected by next-gen encryption.
          </p>
          <button className="primary-cta small-cta" type="button">Explore Storefront</button>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="mesh-shape" />
        </div>
      </section>

      <section className="home-grid">
        <div className="left-stack">
          <article className="accent-stat-card">
            <span>Featured Categories</span>
            <strong>{categories.length}</strong>
            <p>Curated segments for peak performance and utility.</p>
          </article>

          <article className="white-stat-card segment-panel">
            <div className="section-head tight-head">
              <div>
                <h3>Catalog Segments</h3>
              </div>
              <button className="segment-filter" type="button" aria-label="Filter catalog segments">≡</button>
            </div>
            <div className="segment-list">
              {categories.map((category) => (
                <div className="segment-row" key={category}>
                  <span>{category}</span>
                  <b>{products.filter((product) => product.category === category).length}</b>
                </div>
              ))}
            </div>
          </article>
        </div>

        <div className="right-stack">
          <section className="inventory-block">
            <div className="section-heading-row">
              <div className="section-title-mark" />
              <h2>Priority Inventory</h2>
              <button className="link-button" type="button">View All</button>
            </div>
            <div className="priority-grid">
              {featuredProducts.map((product, index) => (
                <article className="priority-card" key={product.id}>
                  <div className="priority-image" style={{ backgroundImage: `url(${product.image})` }} />
                  <div className="priority-copy">
                    {index === 0 ? <span className="product-chip">New</span> : null}
                    <strong>{product.name}</strong>
                    <span className="product-price">${product.price.toFixed(2)}</span>
                    <button className="ghost-action" onClick={() => addProductToCart(product)} type="button">Add</button>
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="inventory-block">
            <div className="section-heading-row">
              <div className="section-title-mark" />
              <h2>Store Inventory</h2>
            </div>
            <div className="store-grid">
              {products.map((product) => (
                <article className="store-card" key={product.id}>
                  <div className="store-image" style={{ backgroundImage: `url(${product.image})` }} />
                  <div className="store-copy">
                    <div className="store-meta-row">
                      <span className="product-meta">{product.category}</span>
                      <span className="product-price">${product.price.toFixed(2)}</span>
                    </div>
                    <div className="store-title-row">
                      <strong>{product.name}</strong>
                    </div>
                    <p>{product.description}</p>
                    <button className="ghost-action" onClick={() => addProductToCart(product)} type="button">Add to Cart</button>
                  </div>
                </article>
              ))}
            </div>
          </section>
        </div>
      </section>
    </AppLayout>
  );
}
