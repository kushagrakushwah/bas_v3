// src/app/page.tsx
"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function Home() {
  const { status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === "unauthenticated") {
      router.push("/login");
    } else if (status === "authenticated") {
      router.push("/dashboard/launch");
    }
  }, [status, router]);

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-black">
      <div className="w-8 h-8 border-4 border-red-500 border-t-transparent rounded-full animate-spin"></div>
    </div>
  );
}