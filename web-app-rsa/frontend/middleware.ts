import { NextRequest, NextResponse } from 'next/server';

const cookieKey = 'quitty_token';
const protectedRoutes = ['/home', '/cart', '/profile'];

export function middleware(request: NextRequest) {
  const token = request.cookies.get(cookieKey)?.value;
  const { pathname } = request.nextUrl;

  if (pathname === '/' && token) {
    return NextResponse.redirect(new URL('/home', request.url));
  }

  if (protectedRoutes.some((route) => pathname.startsWith(route)) && !token) {
    return NextResponse.redirect(new URL('/', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/', '/home/:path*', '/cart/:path*', '/profile/:path*']
};
