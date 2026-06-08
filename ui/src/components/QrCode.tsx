import { useEffect, useState } from "react";
import QRCode from "qrcode";

/**
 * Renders `value` as a scannable QR code. Generation happens client-side via
 * the `qrcode` library (no network round-trip), producing a PNG data URL we
 * drop into an <img>. Used in onboarding so an operator can enrol their first
 * device by scanning the claim token with the mobile agent.
 */
export function QrCode({ value, size = 160 }: { value: string; size?: number }) {
  const [src, setSrc] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    setFailed(false);
    QRCode.toDataURL(value, {
      width: size,
      margin: 1,
      errorCorrectionLevel: "M",
      color: { dark: "#0b1220", light: "#ffffff" },
    })
      .then((url) => {
        if (active) setSrc(url);
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, [value, size]);

  if (failed) {
    return (
      <div className="qr" style={{ width: size, height: size }}>
        <span className="muted" style={{ color: "#0b1220", fontSize: 12 }}>
          QR unavailable
        </span>
      </div>
    );
  }

  return (
    <div className="qr">
      {src ? (
        <img src={src} width={size} height={size} alt="Device enrollment QR code" />
      ) : (
        <div className="skeleton" style={{ width: size, height: size }} />
      )}
    </div>
  );
}
