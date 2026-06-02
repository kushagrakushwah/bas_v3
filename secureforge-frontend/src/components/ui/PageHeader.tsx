interface Props {
  title: string;
  description: string;
}

export default function PageHeader({
  title,
  description,
}: Props) {
  return (
    <div className="mb-10">
      <h1 className="text-5xl font-bold tracking-tight">
        {title}
      </h1>

      <p className="mt-3 text-lg text-white/50">
        {description}
      </p>
    </div>
  );
}