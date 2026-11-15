// Types and callables for the plugin's Python backend.
import { callable } from "@decky/api";

export type Device = {
  deviceId: string;
  name: string;
  createdAt: number;
  connected: boolean;
};

export type Pairing = { uri: string; expiresInS: number };

export type PanelState = {
  listening: boolean;
  error: string | null;
  devices: Device[];
  pairing: Pairing | null;
};

export const getState = callable<[], PanelState>("get_state");
export const startPairing = callable<[], PanelState>("start_pairing");
export const cancelPairing = callable<[], PanelState>("cancel_pairing");
export const removeDevice = callable<[deviceId: string], PanelState>("remove_device");
export const removeAllDevices = callable<[], PanelState>("remove_all_devices");
