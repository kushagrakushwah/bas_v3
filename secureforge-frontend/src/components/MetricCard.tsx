import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  color?: "purple" | "red" | "green" | "amber";
}

export default function MetricCard({
  title,
  value,
  icon: Icon,
  trend,
  color = "purple",
}: MetricCardProps) {
  const colors = {
    purple:
      "from-purple-500/20 to-purple-700/5 border-purple-500/20",
    red:
      "from-red-500/20 to-red-700/5 border-red-500/20",
    green:
      "from-green-500/20 to-green-700/5 border-green-500/20",
    amber:
      "from-amber-500/20 to-amber-700/5 border-amber-500/20",
  };

  return (
    <div
      className={`
        metric-glow
        rounded-3xl
        border
        bg-gradient-to-br
        ${colors[color]}
        backdrop-blur-xl
        p-6
        transition-all
        duration-300
      `}
    >
      <div className="flex items-center justify-between">
        <p className="text-xs uppercase tracking-[0.25em] text-white/40">
          {title}
        </p>

        <Icon className="w-5 h-5 text-white/50" />
      </div>

      <h3 className="mt-4 text-5xl font-bold text-white">
        {value}
      </h3>

      {trend && (
        <p className="mt-3 text-sm text-white/50">
          {trend}
        </p>
      )}
    </div>
  );
}