"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { useEffect, useState } from "react";
import {
  Activity,
  Bell,
  BarChart3,
  HardDrive,
  LogOut,
  Rocket,
  Shield,
  ShieldCheck,
  Target,
  User,
  Clock,
  Cpu,
  ChevronRight,
} from "lucide-react";

const navigation = [
  { name: "Launch Center",      href: "/dashboard/launch",         icon: Rocket,      group: "Operations" },
  { name: "Live Operations",    href: "/dashboard/realtime",       icon: Activity,    group: "Operations" },
  { name: "MITRE ATT&CK",      href: "/dashboard/mitre",          icon: Target,      group: "Intelligence" },
  { name: "SOC Validation",     href: "/dashboard/soc",            icon: ShieldCheck, group: "Intelligence" },
  { name: "Analytics",          href: "/dashboard/analytics",      icon: BarChart3,   group: "Intelligence" },
  { name: "Infrastructure",     href: "/dashboard/infrastructure", icon: HardDrive,   group: "Platform" },
  { name: "Reports & Alerts",   href: "/dashboard/alerts",         icon: Bell,        group: "Platform" },
];

const groups = ["Operations", "Intelligence", "Platform"];

function LiveClock() {
  const [time, setTime] = useState("");
  useEffect(() => {
    const tick = () => {
      setTime(new Date().toLocaleTimeString("en-US", {
        timeZone: "Asia/Kolkata",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }));
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return <span className="font-mono text-sm text-white/70 tabular-nums">{time} IST</span>;
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: session } = useSession();
  const [healthy, setHealthy] = useState<boolean | null>(null);

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch("/api/proxy/api/v1/health", { cache: "no-store" });
        setHealthy(res.ok);
      } catch {
        setHealthy(false);
      }
    };
    check();
    const id = setInterval(check, 15000);
    return () => clearInterval(id);
  }, []);

  // Breadcrumb from pathname
  const crumbs = pathname.replace("/dashboard", "").split("/").filter(Boolean);
  const currentPage = navigation.find(n => n.href === pathname);

  return (
    <div className="min-h-screen flex bg-[#050505] text-white">
      {/* ── SIDEBAR ─────────────────────────────────────────────────────── */}
      <aside className="w-[260px] border-r border-white/[0.07] bg-black/60 backdrop-blur-2xl flex flex-col justify-between flex-shrink-0">
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="px-5 pt-6 pb-4">
            <Link href="/dashboard" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 via-purple-600 to-indigo-700 flex items-center justify-center shadow-lg shadow-purple-500/40 flex-shrink-0">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="font-bold text-base tracking-tight">SecureForge</h1>
                <p className="text-[10px] text-white/40 uppercase tracking-widest mt-0.5">BAS Platform</p>
              </div>
            </Link>
          </div>

          {/* Status Badge */}
          <div className="px-4 mb-4">
            <div className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-white/[0.02] px-3.5 py-2.5">
              <div className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-white/30" />
                <span className="text-xs text-white/50">Engine Status</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${
                  healthy === null ? "bg-amber-400 animate-pulse" :
                  healthy ? "bg-emerald-400 animate-pulse" : "bg-red-400"
                }`} />
                <span className={`text-[10px] font-semibold uppercase tracking-wider ${
                  healthy === null ? "text-amber-400" :
                  healthy ? "text-emerald-400" : "text-red-400"
                }`}>
                  {healthy === null ? "Checking" : healthy ? "Online" : "Degraded"}
                </span>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-3 space-y-5 overflow-y-auto">
            {groups.map(group => {
              const items = navigation.filter(n => n.group === group);
              return (
                <div key={group}>
                  <p className="px-3 mb-1.5 text-[9px] font-bold uppercase tracking-[0.2em] text-white/25">
                    {group}
                  </p>
                  <div className="space-y-0.5">
                    {items.map(item => {
                      const Icon = item.icon;
                      const active = pathname === item.href;
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all duration-200 group relative ${
                            active
                              ? "bg-violet-500/15 text-violet-300 border border-violet-500/25 shadow-sm shadow-violet-500/10"
                              : "text-white/50 hover:text-white/80 hover:bg-white/[0.04]"
                          }`}
                        >
                          {active && (
                            <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-violet-400 rounded-r-full" />
                          )}
                          <Icon className={`w-4 h-4 flex-shrink-0 ${active ? "text-violet-400" : "text-white/35 group-hover:text-white/60"}`} />
                          <span className="font-medium">{item.name}</span>
                        </Link>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </nav>

          {/* User section */}
          <div className="p-4 mt-auto border-t border-white/[0.06]">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center flex-shrink-0">
                <User className="w-4 h-4 text-white" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold truncate">{session?.user?.name || "Operator"}</p>
                <p className="text-[10px] text-white/40 truncate">{session?.user?.email || "Active Session"}</p>
              </div>
            </div>
            <button
              onClick={() => signOut({ callbackUrl: "/login" })}
              className="w-full flex items-center justify-center gap-2 rounded-xl border border-red-500/20 bg-red-500/[0.06] py-2 text-red-400 hover:bg-red-500/15 hover:border-red-500/30 transition-all text-xs font-medium"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      {/* ── MAIN AREA ───────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-16 border-b border-white/[0.07] bg-black/40 backdrop-blur-xl flex items-center justify-between px-6 flex-shrink-0">
          {/* Breadcrumb */}
          <div className="flex items-center gap-1.5 text-sm">
            <span className="text-white/30 font-medium">Dashboard</span>
            {crumbs.map((c, i) => (
              <span key={i} className="flex items-center gap-1.5">
                <ChevronRight className="w-3.5 h-3.5 text-white/20" />
                <span className={i === crumbs.length - 1 ? "text-white/80 font-semibold capitalize" : "text-white/40 capitalize"}>
                  {c === "realtime" ? "Live Operations" : c === "soc" ? "SOC Validation" : c}
                </span>
              </span>
            ))}
          </div>

          {/* Right side */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-white/40">
              <Clock className="w-3.5 h-3.5" />
              <LiveClock />
            </div>
            <div className="h-4 w-px bg-white/10" />
            <div className="flex items-center gap-2 rounded-xl border border-violet-500/20 bg-violet-500/[0.06] px-3 py-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
              <span className="text-xs font-medium text-violet-300">Event Stream Active</span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}