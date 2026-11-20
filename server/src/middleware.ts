import { NextResponse, type NextRequest } from 'next/server';

// Expose the requested path+query to server components via a request header, so requireUser() can send an
// unauthenticated visitor to /login?next=<original URL> and return them there after they sign in. Without
// this, a deep link (e.g. an e-mail link to a specific finding) is lost at the login bounce and the user
// lands on the home dashboard instead of the page they clicked. This middleware does no auth itself.
export function middleware(req: NextRequest) {
  const headers = new Headers(req.headers);
  headers.set('x-pathname', req.nextUrl.pathname + req.nextUrl.search);
  return NextResponse.next({ request: { headers } });
}

export const config = {
  matcher: ['/((?!_next/|api/|favicon|icon|manifest|.*\\.).*)'],
};
