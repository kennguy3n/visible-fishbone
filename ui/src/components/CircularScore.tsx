/**
 * Circular progress ring used for the dashboard "Security Score" hero. The
 * arc length encodes `value` (0–100) and the colour follows the same
 * thresholds the product uses elsewhere: green > 80, amber > 50, red ≤ 50.
 */
function scoreTone(value: number): "ok" | "warn" | "danger" {
  if (value > 80) return "ok";
  if (value > 50) return "warn";
  return "danger";
}

const TONE_COLOR: Record<string, string> = {
  ok: "var(--ok)",
  warn: "var(--warn)",
  danger: "var(--danger)",
};

export function CircularScore({
  value,
  size = 168,
  caption = "Security score",
}: {
  value: number | null | undefined;
  size?: number;
  caption?: string;
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(value ?? 0)));
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - clamped / 100);
  const tone = scoreTone(clamped);
  const color = TONE_COLOR[tone];
  const center = size / 2;

  return (
    <div
      className="score-ring"
      style={{ ["--ring-size" as string]: `${size}px` }}
      role="img"
      aria-label={`${caption}: ${value == null ? "not available" : `${clamped} out of 100`}`}
    >
      <svg viewBox={`0 0 ${size} ${size}`}>
        <circle
          className="score-ring__track"
          cx={center}
          cy={center}
          r={radius}
          strokeWidth={stroke}
        />
        <circle
          className="score-ring__value"
          cx={center}
          cy={center}
          r={radius}
          strokeWidth={stroke}
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={value == null ? circumference : offset}
        />
      </svg>
      <div className="score-ring__label">
        <div>
          <span className="score-ring__num" style={{ color }}>
            {value == null ? "—" : clamped}
          </span>
          <span className="score-ring__cap">{caption}</span>
        </div>
      </div>
    </div>
  );
}
