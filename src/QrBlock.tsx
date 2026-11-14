// Shows the pairing QR code with a local expiry countdown.
import { PanelSectionRow } from "@decky/ui";
import { QRCodeSVG } from "qrcode.react";
import { useEffect, useState } from "react";
import type { Pairing } from "./backend";

function formatRemaining(seconds: number): string {
  const s = String(seconds % 60).padStart(2, "0");
  return `${Math.floor(seconds / 60)}:${s}`;
}

export function QrBlock({ pairing, onExpire }: { pairing: Pairing; onExpire: () => void }) {
  const [remaining, setRemaining] = useState(pairing.expiresInS);

  // The backend counts expiresInS from the moment it answered, so a deadline is fixed on arrival.
  useEffect(() => {
    const deadline = Date.now() + pairing.expiresInS * 1000;
    const tick = () => {
      const left = Math.ceil((deadline - Date.now()) / 1000);
      if (left <= 0) {
        clearInterval(timer);
        onExpire();
      } else {
        setRemaining(left);
      }
    };
    const timer = setInterval(tick, 250);
    setRemaining(pairing.expiresInS);
    return () => clearInterval(timer);
  }, [pairing, onExpire]);

  return (
    <PanelSectionRow>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
        <div style={{ background: "#fff", borderRadius: 8, lineHeight: 0, width: 220, height: 220 }}>
          <QRCodeSVG value={pairing.uri} size={220} level="L" marginSize={4} bgColor="#ffffff" fgColor="#000000" />
        </div>
        <div style={{ opacity: 0.7 }}>Scan with the HotBar app.</div>
        <div style={{ opacity: 0.7 }}>Expires in {formatRemaining(remaining)}</div>
      </div>
    </PanelSectionRow>
  );
}
