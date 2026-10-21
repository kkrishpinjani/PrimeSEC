import "next-auth";
import "next-auth/jwt";

declare module "next-auth" {
  interface Session {
    user: {
      name?: string | null;
      email?: string | null;
      image?: string | null;
      roles: string[];
      isPrimeSecAdmin: boolean;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    roles?: string[];
    issuer?: string;
    idToken?: string;
  }
}
