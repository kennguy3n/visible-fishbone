/**
 * Geographic data for the dashboard threat map. Kept in its own module (no
 * component exports) so the map component and the dashboard can both import it
 * without tripping react-refresh's "only export components" rule.
 */

export interface ThreatPoint {
  id: string;
  label: string;
  lat: number;
  lng: number;
  count: number;
}

/** Factual centroids for common cloud regions and country codes. */
export const REGION_COORDS: Record<
  string,
  { lat: number; lng: number; label: string }
> = {
  "us-east-1": { lat: 38.0, lng: -78.5, label: "US East (Virginia)" },
  "us-east-2": { lat: 40.0, lng: -83.0, label: "US East (Ohio)" },
  "us-west-1": { lat: 37.4, lng: -122.0, label: "US West (N. California)" },
  "us-west-2": { lat: 45.5, lng: -122.7, label: "US West (Oregon)" },
  "ca-central-1": { lat: 45.5, lng: -73.6, label: "Canada (Central)" },
  "eu-west-1": { lat: 53.3, lng: -6.3, label: "EU West (Ireland)" },
  "eu-west-2": { lat: 51.5, lng: -0.1, label: "EU West (London)" },
  "eu-central-1": { lat: 50.1, lng: 8.7, label: "EU Central (Frankfurt)" },
  "eu-north-1": { lat: 59.3, lng: 18.1, label: "EU North (Stockholm)" },
  "ap-south-1": { lat: 19.1, lng: 72.9, label: "Asia Pacific (Mumbai)" },
  "ap-southeast-1": { lat: 1.35, lng: 103.8, label: "Asia Pacific (Singapore)" },
  "ap-southeast-2": { lat: -33.9, lng: 151.2, label: "Asia Pacific (Sydney)" },
  "ap-northeast-1": { lat: 35.7, lng: 139.7, label: "Asia Pacific (Tokyo)" },
  "sa-east-1": { lat: -23.5, lng: -46.6, label: "South America (São Paulo)" },
  "af-south-1": { lat: -33.9, lng: 18.4, label: "Africa (Cape Town)" },
  "me-south-1": { lat: 26.1, lng: 50.6, label: "Middle East (Bahrain)" },
};
