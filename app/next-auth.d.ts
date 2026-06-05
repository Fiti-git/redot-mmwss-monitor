import "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id?: string;
      email?: string | null;
      name?: string | null;
      role?: "admin" | "viewer";
    };
  }

  interface User {
    role?: "admin" | "viewer";
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    uid?: string;
    role?: "admin" | "viewer";
  }
}
