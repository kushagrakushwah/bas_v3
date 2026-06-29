"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";

import {
  Activity,
  Bell,
  BarChart3,
  FileText,
  HardDrive,
  LogOut,
  Rocket,
  Shield,
  ShieldCheck,
  Target,
  User,
} from "lucide-react";

const navigation = [
  {
    name: "Launch Center",
    href: "/dashboard/launch",
    icon: Rocket,
  },
  {
    name: "Live Operations",
    href: "/dashboard/realtime",
    icon: Activity,
  },
  {
    name: "MITRE ATT&CK",
    href: "/dashboard/mitre",
    icon: Target,
  },
  {
    name: "SOC Validation",
    href: "/dashboard/soc",
    icon: ShieldCheck,
  },
  {
    name: "Analytics",
    href: "/dashboard/analytics",
    icon: BarChart3,
  },
  {
    name: "Infrastructure",
    href: "/dashboard/infrastructure",
    icon: HardDrive,
  },

  {
    name: "Reports and Alerts",
    href: "/dashboard/alerts",
    icon: Bell,
  },
];

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  const { data: session } = useSession();

  return (
    <div className="min-h-screen flex bg-[#050505] text-white">
      {/* SIDEBAR */}

      <aside className="w-[280px] border-r border-white/10 backdrop-blur-xl bg-black/40 flex flex-col justify-between">
        <div>
          {/* LOGO */}

          <div className="p-8">
            <div className="flex items-center gap-3">
              <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-purple-500 to-purple-700 flex items-center justify-center shadow-lg shadow-purple-500/30">
                <Shield className="w-6 h-6 text-white" />
              </div>

              <div>
                <h1 className="font-bold text-xl">
                  SecureForge
                </h1>

                <p className="text-xs text-white/50">
                  BAS Platform
                </p>
              </div>
            </div>
          </div>

          {/* STATUS */}

          <div className="px-6 mb-8">
            <div className="glass-card p-4">
              <div className="flex items-center justify-between">
                <span className="text-white/60 text-sm">
                  Platform Status
                </span>

                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />

                  <span className="text-green-400 text-xs">
                    ONLINE
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* NAVIGATION */}

          <nav className="px-4 space-y-2">
            {navigation.map((item) => {
              const Icon = item.icon;

              const active =
                pathname === item.href;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`
                    flex
                    items-center
                    gap-3
                    px-4
                    py-3
                    rounded-xl
                    transition-all
                    duration-300
                    ${
                      active
                        ? "bg-purple-500/15 border border-purple-500/30 text-purple-300 shadow-lg shadow-purple-500/10"
                        : "text-white/60 hover:text-white hover:bg-white/5"
                    }
                  `}
                >
                  <Icon className="w-5 h-5" />

                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* USER SECTION */}

        <div className="p-5">
          <div className="glass-card p-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-purple-600 flex items-center justify-center">
                <User className="w-5 h-5" />
              </div>

              <div>
                <p className="font-medium">
                  {session?.user?.name || "Operator"}
                </p>

                <p className="text-xs text-white/50">
                  Active Session
                </p>
              </div>
            </div>

            <button
              onClick={() =>
                signOut({
                  callbackUrl: "/login",
                })
              }
              className="
                w-full
                flex
                items-center
                justify-center
                gap-2
                rounded-xl
                border
                border-red-500/20
                bg-red-500/10
                py-2.5
                text-red-400
                hover:bg-red-500/20
                transition-all
              "
            >
              <LogOut className="w-4 h-4" />

              Logout
            </button>
          </div>
        </div>
      </aside>

      {/* MAIN AREA */}

      <div className="flex-1 flex flex-col">
        {/* TOP BAR */}

        <header className="h-20 border-b border-white/10 bg-black/20 backdrop-blur-xl flex items-center justify-between px-8">
          <div>
            <h2 className="text-lg font-semibold">
              SecureForge BAS Console
            </h2>

            <p className="text-sm text-white/50">
              Breach & Attack Simulation Platform
            </p>
          </div>

          <div className="flex items-center gap-4">
            <div className="glass-card px-4 py-2 flex items-center gap-3">
              <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse" />

              <span className="text-sm text-white/70">
                Event Stream Active
              </span>
            </div>
          </div>
        </header>

        {/* PAGE CONTENT */}

        <main className="flex-1 overflow-y-auto p-8">
          {children}
        </main>
      </div>
    </div>
  );
}