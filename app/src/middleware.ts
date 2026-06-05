export { default } from "next-auth/middleware";

export const config = {
  // Protect everything except login and NextAuth's own routes.
  // (basePath '/mmwss' is applied automatically — these paths are AFTER the basePath.)
  matcher: ["/((?!login|api/auth|_next/static|_next/image|favicon.ico|redot-icon).*)"],
};
