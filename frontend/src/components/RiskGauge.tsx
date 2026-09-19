interface RiskGaugeProps {
  score: number;
  label?: string;
  size?: number;
}

function riskBand(score: number): { name: string; color: string } {
  if (score >= 0.82) return { name: "Critical", color: "var(--danger)" };
  if (score >= 0.55) return { name: "Review", color: "var(--warning)" };
  return { name: "Low", color: "var(--success)" };
}

export function RiskGauge({ score, label = "Average risk", size = 168 }: RiskGaugeProps) {
  const normalized = Math.max(0, Math.min(1, Number.isFinite(score) ? score : 0));
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - normalized);
  const band = riskBand(normalized);

  return (
    <figure className="risk-gauge" aria-label={`${label}: ${Math.round(normalized * 100)} percent`}>
      <svg width={size} height={size} viewBox="0 0 160 160" role="img">
        <title>{`${label}: ${Math.round(normalized * 100)}%, ${band.name}`}</title>
        <circle className="risk-gauge__track" cx="80" cy="80" r={radius} />
        <circle
          className="risk-gauge__value"
          cx="80"
          cy="80"
          r={radius}
          stroke={band.color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
        <text className="risk-gauge__score" x="80" y="75" textAnchor="middle">
          {Math.round(normalized * 100)}
        </text>
        <text className="risk-gauge__percent" x="80" y="95" textAnchor="middle">
          percent
        </text>
      </svg>
      <figcaption>
        <strong>{label}</strong>
        <span style={{ color: band.color }}>{band.name}</span>
      </figcaption>
    </figure>
  );
}
