import { getToken } from "next-auth/jwt";
import { NextResponse, type NextRequest } from "next/server";

// NOTE: middleware runs on the Edge Runtime with a 1 MB bundle limit (Vercel
// Hobby). It must NOT import lib/auth (which pulls in Prisma + bcrypt).
// Sessions use the JWT strategy, so role checks only need the token.

const PROTECTED: Array<{ prefix: string; roles: string[] }> = [
  { prefix: "/tourist", roles: ["TOURIST", "ADMIN"] },
  { prefix: "/guide", roles: ["GUIDE", "ADMIN"] },
  { prefix: "/admin", roles: ["ADMIN"] },
];

export default async function middleware(req: NextRequest) {
  const { nextUrl } = req;
  const token = await getToken({ req, secret: process.env.AUTH_SECRET });
  const role = token?.role as string | undefined;

  for (const { prefix, roles } of PROTECTED) {
    if (nextUrl.pathname.startsWith(prefix) && (!role || !roles.includes(role))) {
      const url = new URL("/auth/signin", nextUrl.origin);
      url.searchParams.set("callbackUrl", nextUrl.pathname);
      return NextResponse.redirect(url);
    }
  }
  return NextResponse.next();
}

export const config = { matcher: ["/tourist/:path*", "/guide/:path*", "/admin/:path*"] };