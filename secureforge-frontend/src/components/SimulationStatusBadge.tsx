interface Props {
  status: string;
}

export default function SimulationStatusBadge({
  status,
}: Props) {
  const value =
    status?.toLowerCase() || "";

  const styles = {
    queued:
      "bg-amber-500/10 border-amber-500/20 text-amber-400",
    running:
      "bg-purple-500/10 border-purple-500/20 text-purple-400",
    completed:
      "bg-green-500/10 border-green-500/20 text-green-400",
    failed:
      "bg-red-500/10 border-red-500/20 text-red-400",
  };

  return (
    <span
      className={`
        inline-flex
        items-center
        px-3
        py-1
        rounded-full
        border
        text-xs
        font-medium
        ${
          styles[
            value as keyof typeof styles
          ] ||
          "bg-white/10 border-white/20 text-white"
        }
      `}
    >
      {status}
    </span>
  );
}