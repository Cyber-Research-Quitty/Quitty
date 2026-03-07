export const authApiUrl = process.env.NEXT_PUBLIC_AUTH_API_URL || 'http://localhost:8001';
export const cartApiUrl = process.env.NEXT_PUBLIC_CART_API_URL || 'http://localhost:8003';
export const productApiUrl = process.env.NEXT_PUBLIC_PRODUCT_API_URL || 'http://localhost:8004';
export const storageKey = 'quitty-session';
export const cookieKey = 'quitty_token';

export function getStoredToken(): string {
  if (typeof window === 'undefined') {
    return '';
  }
  return window.localStorage.getItem(storageKey) || '';
}

export function persistToken(token: string) {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.setItem(storageKey, token);
  document.cookie = `${cookieKey}=${token}; path=/; max-age=86400; samesite=lax`;
}

export function clearStoredToken() {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.removeItem(storageKey);
  document.cookie = `${cookieKey}=; path=/; max-age=0; samesite=lax`;
}

export function authHeaders(token: string): HeadersInit {
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json'
  };
}
