// src/app/login/page.tsx
"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { Shield, Terminal, Lock, User, ArrowRight, Activity } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    const res = await signIn("credentials", {
      redirect: false,
      username,
      password,
    });

    if (res?.error) {
      setError("Authorization denied. Invalid operator signature.");
      setLoading(false);
    } else {
      router.push("/dashboard/launch");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden selection:bg-neon-purple/30 selection:text-white">
      
      {/* Background Layer: Animated Neon Orbs & Grid */}
      <div className="absolute inset-0 bg-grid-pattern opacity-40 pointer-events-none"></div>
      <div className="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] bg-neon-purple/20 blur-[150px] rounded-full mix-blend-screen animate-glow-pulse pointer-events-none"></div>
      <div className="absolute bottom-[-20%] right-[-10%] w-[60%] h-[60%] bg-neon-blue/20 blur-[150px] rounded-full mix-blend-screen animate-glow-pulse pointer-events-none" style={{ animationDelay: '1.5s' }}></div>
      
      {/* Scanline Overlay */}
      <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(0,0,0,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_4px,3px_100%] z-0 opacity-20"></div>

      {/* Main Glass Panel */}
      <div className="w-full max-w-md p-8 sm:p-10 bg-surface/40 backdrop-blur-2xl border border-surfaceBorder rounded-3xl shadow-[0_8px_32px_0_rgba(0,0,0,0.5)] relative z-10 transform transition-all animate-fade-in">
        
        {/* Header Segment */}
        <div className="flex flex-col items-center mb-10">
          <div className="relative group mb-6">
            <div className="absolute inset-0 bg-gradient-to-r from-neon-purple to-neon-blue blur-xl opacity-50 group-hover:opacity-80 transition-opacity duration-500 rounded-full"></div>
            <div className="relative p-4 bg-black/50 rounded-2xl border border-white/10 shadow-inner">
              <Shield className="w-10 h-10 text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.5)]" />
            </div>
          </div>
          <h1 className="text-3xl font-black tracking-widest bg-clip-text text-transparent bg-gradient-to-r from-white via-zinc-200 to-zinc-500 drop-shadow-sm">
            SECUREFORGE
          </h1>
          <p className="text-[10px] font-mono text-neon-blue mt-3 flex items-center gap-2 px-3 py-1 bg-neon-blue/10 rounded-full border border-neon-blue/20 uppercase tracking-widest shadow-[0_0_10px_rgba(59,130,246,0.2)]">
            <Terminal className="w-3 h-3" />
            Tactical BAS Engine
          </p>
        </div>

        {/* Authentication Form */}
        <form onSubmit={handleLogin} className="space-y-6">
          
          {/* Username Input */}
          <div className="space-y-2 relative group">
            <label className="text-xs font-bold text-zinc-400 uppercase tracking-widest pl-1">Operator ID</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <User className="w-4 h-4 text-zinc-500 group-focus-within:text-neon-purple transition-colors" />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-black/20 border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-neon-purple focus:border-transparent transition-all font-mono placeholder:text-zinc-700 hover:bg-black/40"
                placeholder="Enter designation..."
                required
              />
            </div>
          </div>

          {/* Password Input */}
          <div className="space-y-2 relative group">
            <label className="text-xs font-bold text-zinc-400 uppercase tracking-widest pl-1">Passphrase</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Lock className="w-4 h-4 text-zinc-500 group-focus-within:text-neon-blue transition-colors" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black/20 border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-neon-blue focus:border-transparent transition-all font-mono placeholder:text-zinc-700 hover:bg-black/40"
                placeholder="••••••••••••"
                required
              />
            </div>
          </div>

          {/* Error State */}
          {error && (
            <div className="p-3.5 bg-neon-red/10 border border-neon-red/30 rounded-xl text-xs text-neon-red flex items-center gap-3 animate-pulse shadow-[0_0_15px_rgba(239,68,68,0.2)] font-mono">
              <Activity className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="relative w-full group mt-4"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-neon-purple to-neon-blue rounded-xl blur opacity-70 group-hover:opacity-100 transition duration-500 group-active:opacity-50"></div>
            <div className="relative flex items-center justify-center gap-3 py-4 bg-background border border-white/10 rounded-xl leading-none transition-all duration-300 group-hover:bg-opacity-0">
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span className="text-white font-bold text-sm uppercase tracking-widest">Authenticating...</span>
                </>
              ) : (
                <>
                  <span className="text-white font-bold text-sm uppercase tracking-widest">Establish Link</span>
                  <ArrowRight className="w-4 h-4 text-white group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </div>
          </button>
        </form>

        {/* Footer */}
        <div className="mt-10 text-center">
          <p className="text-[9px] text-zinc-600 font-mono tracking-widest leading-relaxed">
            RESTRICTED MILITARY/CORPORATE NODE.<br/>
            UNAUTHORIZED ACCESS WILL TRIGGER DEFENSIVE PROTOCOLS.
          </p>
        </div>
      </div>
    </div>
  );
}