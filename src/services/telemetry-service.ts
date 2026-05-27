// Telemetry is opt-in only. No data is sent unless the user explicitly enables it.
// This module is a no-op placeholder ready for future implementation.

export interface TelemetryEvent {
  name: string;
  properties?: Record<string, string>;
  measurements?: Record<string, number>;
}

let telemetryEnabled = false;

export function setTelemetryEnabled(enabled: boolean): void {
  telemetryEnabled = enabled;
}

export function trackEvent(_event: TelemetryEvent): void {
  if (!telemetryEnabled) { return; }
  // Future: send to telemetry backend after explicit user consent
}
