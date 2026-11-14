// Quick access panel for the HotBar Decky plugin: pairing QR code and the list of paired devices.
import {
  ButtonItem,
  ConfirmModal,
  DialogButton,
  Field,
  PanelSection,
  PanelSectionRow,
  showModal,
  staticClasses,
} from "@decky/ui";
import { addEventListener, definePlugin, removeEventListener } from "@decky/api";
import { useCallback, useEffect, useRef, useState } from "react";
import { FaKeyboard } from "react-icons/fa";
import {
  cancelPairing,
  Device,
  getState,
  PanelState,
  removeAllDevices,
  removeDevice,
  startPairing,
} from "./backend";
import { QrBlock } from "./QrBlock";

const ABOUT_TEXT =
  "Your phone and this device must be on the same local network. Scan the code with the HotBar app. " +
  "Removing a device here stops it from sending input at once.";

function statusText(state: PanelState): string {
  if (!state.listening) return state.error ? `Not running. ${state.error}` : "Not running";
  const total = state.devices.length;
  const connected = state.devices.filter((d) => d.connected).length;
  const base = total === 0 ? "No devices paired" : total === 1 ? "1 device paired" : `${total} devices paired`;
  return connected > 0 ? `${base}, ${connected} connected` : base;
}

function StatusRow({ state }: { state: PanelState }) {
  const color = !state.listening ? "#d33" : state.devices.some((d) => d.connected) ? "#3c3" : "#888";
  return (
    <PanelSectionRow>
      <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14 }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, flexShrink: 0 }} />
        <span>{statusText(state)}</span>
      </div>
    </PanelSectionRow>
  );
}

function DeviceRow({ device, onRemove }: { device: Device; onRemove: () => void }) {
  return (
    <PanelSectionRow>
      <Field
        label={
          <span
            style={{
              display: "block",
              minWidth: 0,
              fontWeight: "bold",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {device.name}
          </span>
        }
        description={device.connected ? "Connected" : undefined}
        childrenContainerWidth="min"
        bottomSeparator="none"
      >
        <DialogButton style={{ minWidth: 0, minHeight: 44, padding: "10px 16px" }} onClick={onRemove}>
          Remove
        </DialogButton>
      </Field>
    </PanelSectionRow>
  );
}

function Content() {
  const [state, setState] = useState<PanelState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const prev = useRef<PanelState | null>(null);
  // Set when this panel itself ended the session, so the null that follows is not shown as an expiry.
  const hiding = useRef(false);

  const apply = useCallback((raw: PanelState) => {
    const next = raw.pairing && raw.pairing.expiresInS <= 0 ? { ...raw, pairing: null } : raw;
    const before = prev.current;
    if (next.pairing) {
      hiding.current = false;
      setExpired(false);
    } else if (
      before?.pairing &&
      !hiding.current &&
      next.devices.every((d) => before.devices.some((o) => o.deviceId === d.deviceId))
    ) {
      setExpired(true);
    }
    prev.current = next;
    setState(next);
  }, []);

  const run = useCallback(
    async (call: () => Promise<PanelState>) => {
      try {
        apply(await call());
        setError(null);
      } catch {
        setError("Could not reach the HotBar backend.");
      }
    },
    [apply],
  );

  useEffect(() => {
    let alive = true;
    const handle = addEventListener<[PanelState]>("hotbar_state", (next) => {
      if (alive) apply(next);
    });
    (async () => {
      try {
        const initial = await getState();
        if (!alive) return;
        apply(initial);
        setError(null);
        if (initial.listening && initial.devices.length === 0) {
          const started = await startPairing();
          if (alive) apply(started);
          else cancelPairing().catch(() => {});
        }
      } catch {
        if (alive) setError("Could not reach the HotBar backend.");
      }
    })();
    return () => {
      alive = false;
      removeEventListener("hotbar_state", handle);
      cancelPairing().catch(() => {});
    };
  }, [apply]);

  const markExpired = useCallback(() => setExpired(true), []);

  const confirmRemove = (device: Device) =>
    showModal(
      <ConfirmModal
        strTitle="Remove device"
        strDescription={`Remove "${device.name}"? It stops sending input at once and has to be paired again.`}
        strOKButtonText="Remove"
        bDestructiveWarning
        onOK={() => void run(() => removeDevice(device.deviceId))}
      />,
    );

  const confirmUnpairAll = () =>
    showModal(
      <ConfirmModal
        strTitle="Unpair all devices"
        strDescription="Every paired device stops sending input at once and has to be paired again."
        strOKButtonText="Unpair all"
        bDestructiveWarning
        onOK={() => void run(removeAllDevices)}
      />,
    );

  const showAbout = () =>
    showModal(<ConfirmModal strTitle="About pairing" strDescription={ABOUT_TEXT} strOKButtonText="OK" bAlertDialog />);

  const devices = state?.devices ?? [];
  const qrActive = !!state?.pairing && !expired;

  const togglePairing = () => {
    if (qrActive) {
      hiding.current = true;
      setExpired(false);
      void run(cancelPairing);
    } else {
      hiding.current = false;
      void run(startPairing);
    }
  };

  return (
    <PanelSection>
      <PanelSectionRow>
        <ButtonItem layout="below" onClick={showAbout}>
          About pairing
        </ButtonItem>
      </PanelSectionRow>
      {state && <StatusRow state={state} />}
      {error && (
        <PanelSectionRow>
          <div>{error}</div>
        </PanelSectionRow>
      )}
      {state?.pairing && qrActive && <QrBlock pairing={state.pairing} onExpire={markExpired} />}
      {expired && (
        <PanelSectionRow>
          <div style={{ textAlign: "center", opacity: 0.7 }}>The QR code expired.</div>
        </PanelSectionRow>
      )}
      {devices.map((d) => (
        <DeviceRow key={d.deviceId} device={d} onRemove={() => confirmRemove(d)} />
      ))}
      {state && (
        <PanelSectionRow>
          <ButtonItem layout="below" disabled={!state.listening} onClick={togglePairing}>
            {qrActive ? "Hide QR code" : devices.length > 0 ? "Pair another device" : "Pair a device"}
          </ButtonItem>
        </PanelSectionRow>
      )}
      {devices.length > 0 && (
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={confirmUnpairAll}>
            Unpair all devices
          </ButtonItem>
        </PanelSectionRow>
      )}
    </PanelSection>
  );
}

export default definePlugin(() => {
  return {
    name: "HotBar",
    titleView: <div className={staticClasses.Title}>HotBar</div>,
    content: <Content />,
    icon: <FaKeyboard />,
  };
});
