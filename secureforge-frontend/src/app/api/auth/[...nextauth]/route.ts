import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

const handler = NextAuth({
  providers: [
    CredentialsProvider({
      name: "SecureForge Console",
      credentials: {
        username: { label: "Username", type: "text" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        // Matches the authentication validation inside dashboard/views/login.py
        if (
          (credentials?.username === "admin" && credentials?.password === "admin123") ||
          (credentials?.username === "operator" && credentials?.password === "operator123")
        ) {
          return { id: "1", name: credentials.username, role: credentials.username === "admin" ? "Administrator" : "Operator" };
        }
        return null;
      }
    })
  ],
  pages: {
    signIn: "/login",
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) token.role = (user as any).role;
      return token;
    },
    async session({ session, token }) {
      if (session.user) (session.user as any).role = token.role;
      return session;
    }
  }
});

export { handler as GET, handler as POST };