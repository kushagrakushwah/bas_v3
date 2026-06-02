interface Props {
  severity: string;
}

export default function SeverityBadge({
  severity,
}: Props) {
  const level =
    severity?.toLowerCase() ||
    "unknown";

  const styles = {
    critical:
      "bg-red-600/20 border-red-500/30 text-red-400",
    high:
      "bg-orange-500/20 border-orange-500/30 text-orange-400",
    medium:
      "bg-amber-500/20 border-amber-500/30 text-amber-400",
    low:
      "bg-green-500/20 border-green-500/30 text-green-400",
  };

  return (
    <span
      className={`
        px-3 py-1 rounded-full text-xs border
        ${
          styles[
            level as keyof typeof styles
          ] ||
          "bg-white/10 border-white/20 text-white"
        }
      `}
    >
      {severity}
    </span>
  );
}