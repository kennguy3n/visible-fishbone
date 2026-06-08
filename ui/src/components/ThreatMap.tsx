/**
 * A lightweight inline-SVG world map that plots blocked-threat activity by
 * geographic region. The control plane has no per-flow geo-IP telemetry
 * endpoint, so the map is fed by the regions we *do* know factually — the
 * tenant's deployment region(s) — sized by the real blocked-threat counts the
 * caller passes in. The continent silhouettes are intentionally stylised; the
 * markers carry the real data.
 *
 * Projection is equirectangular over a 360×180 viewBox so a (lng, lat) pair
 * maps directly to (lng + 180, 90 − lat).
 */
import type { ThreatPoint } from "./threat-regions";

export type { ThreatPoint } from "./threat-regions";

// Stylised continent silhouettes in the 360×180 projection space.
const CONTINENTS = [
  "M30,40 L70,30 L98,34 L96,52 L78,64 L70,82 L58,96 L46,84 L34,70 L26,54 Z",
  "M104,96 L128,90 L140,104 L138,128 L122,150 L110,150 L102,124 L106,108 Z",
  "M168,34 L196,26 L214,32 L208,46 L190,52 L176,48 Z",
  "M168,56 L210,52 L226,70 L224,98 L206,124 L188,124 L176,96 L166,74 Z",
  "M220,30 L286,22 L330,38 L322,64 L292,74 L262,66 L236,72 L222,52 Z",
  "M296,104 L332,100 L338,118 L320,130 L300,126 Z",
];

function project(lng: number, lat: number): [number, number] {
  return [lng + 180, 90 - lat];
}

export function ThreatMap({ points }: { points: ThreatPoint[] }) {
  const max = points.reduce((m, p) => Math.max(m, p.count), 0) || 1;

  return (
    <div className="threat-map">
      <svg viewBox="0 0 360 180" role="img" aria-label="Blocked threat activity by region">
        {CONTINENTS.map((d, i) => (
          <path key={i} d={d} className="threat-map__land" />
        ))}
        {points.map((p) => {
          const [x, y] = project(p.lng, p.lat);
          const r = 2.5 + (p.count / max) * 7;
          return (
            <g key={p.id}>
              <circle className="threat-map__pulse" cx={x} cy={y} r={r * 2.1} />
              <circle className="threat-map__marker" cx={x} cy={y} r={r}>
                <title>
                  {p.label}: {p.count} blocked
                </title>
              </circle>
            </g>
          );
        })}
      </svg>
      <div className="threat-legend">
        {points.length === 0 ? (
          <span className="muted">
            No blocked-threat activity attributed to a known region yet.
          </span>
        ) : (
          points.map((p) => (
            <span key={p.id} className="threat-legend__item">
              <span
                className="qa-item__dot"
                style={{ background: "var(--danger)" }}
              />
              {p.label} · <b>{p.count.toLocaleString()}</b>
            </span>
          ))
        )}
      </div>
    </div>
  );
}
