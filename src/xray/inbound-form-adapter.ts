import { canEnableSniffing } from './protocol-capabilities';
import { normalizeStreamSettingsForWire } from './stream-wire-normalize';

export interface RawInboundRow {
  port?: number;
  listen?: string;
  protocol?: string;
  tag?: string;
  settings?: unknown;
  streamSettings?: unknown;
  sniffing?: unknown;
  up?: number;
  down?: number;
  total?: number;
  remark?: string;
  enable?: boolean;
  expiryTime?: number;
  trafficReset?: string;
  lastTrafficResetTime?: number;
  nodeId?: number | null;
  shareAddrStrategy?: string;
  shareAddr?: string;
  subSortIndex?: number;
}

export interface WireInboundPayload {
  up: number;
  down: number;
  total: number;
  remark: string;
  enable: boolean;
  expiryTime: number;
  trafficReset: string;
  lastTrafficResetTime: number;
  listen: string;
  port: number;
  protocol: string;
  settings: string;
  streamSettings: string;
  sniffing: string;
  tag: string;
  nodeId?: number;
  shareAddrStrategy: string;
  shareAddr: string;
  subSortIndex: number;
}

/**
 * Recursively removes empty values from arrays or objects.
 */
export function pruneEmpty(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(pruneEmpty);
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const p = pruneEmpty(v);
      if (p === undefined) continue;
      out[k] = p;
    }
    return out;
  }
  return value;
}

/**
 * Clears obsolete fallback configurations and final mask structures.
 */
export function dropLegacyOptionalEmpties(
  settings: Record<string, unknown>,
  stream: Record<string, unknown> | undefined
): void {
  const fb = settings['fallbacks'];
  if (Array.isArray(fb) && fb.length === 0) delete settings['fallbacks'];

  if (stream) {
    const fm = stream['finalmask'] as
      | { tcp?: unknown[]; udp?: unknown[]; quicParams?: unknown }
      | undefined;
    if (fm && typeof fm === 'object') {
      const hasTcp = Array.isArray(fm.tcp) && fm.tcp.length > 0;
      const hasUdp = Array.isArray(fm.udp) && fm.udp.length > 0;
      const hasQuic = fm.quicParams != null;
      if (!hasTcp && !hasUdp && !hasQuic) {
        delete stream['finalmask'];
      } else {
        if (!hasTcp) delete fm.tcp;
        if (!hasUdp) delete fm.udp;
      }
    }

    const hs = stream['hysteriaSettings'] as { auth?: string } | undefined;
    if (hs && typeof hs === 'object' && (hs.auth === '' || hs.auth == null)) {
      delete hs.auth;
    }
  }
}

/**
 * Standardizes traffic sniffing configuration options.
 */
export function normalizeSniffing(s: any | undefined): Record<string, unknown> {
  if (!s || !s['enabled']) return { enabled: false };
  const out: Record<string, unknown> = {
    enabled: true,
    destOverride: s['destOverride'],
  };
  if (s['metadataOnly']) out['metadataOnly'] = true;
  if (s['routeOnly']) out['routeOnly'] = true;
  if (s['ipsExcluded']?.length) out['ipsExcluded'] = s['ipsExcluded'];
  if (s['domainsExcluded']?.length) out['domainsExcluded'] = s['domainsExcluded'];
  return out;
}

/**
 * Converts form configurations into wire payload format.
 */
export function formValuesToWirePayload(values: any): WireInboundPayload {
  const settingsPruned = (pruneEmpty(values.settings ?? {}) ?? {}) as Record<string, unknown>;
  let streamPruned = values.streamSettings
    ? ((pruneEmpty(values.streamSettings) ?? {}) as Record<string, unknown>)
    : undefined;
  if (streamPruned) {
    streamPruned = normalizeStreamSettingsForWire(streamPruned, { side: 'inbound' });
  }
  dropLegacyOptionalEmpties(settingsPruned, streamPruned);

  const payload: WireInboundPayload = {
    up: values.up ?? 0,
    down: values.down ?? 0,
    total: values.total ?? 0,
    remark: values.remark ?? '',
    enable: values.enable ?? true,
    expiryTime: values.expiryTime ?? 0,
    trafficReset: values.trafficReset ?? 'never',
    lastTrafficResetTime: values.lastTrafficResetTime ?? 0,
    listen: values.listen ?? '',
    port: values.port ?? 0,
    protocol: values.protocol,
    settings: JSON.stringify(settingsPruned),
    streamSettings: streamPruned ? JSON.stringify(streamPruned) : '',
    sniffing: canEnableSniffing({ protocol: values.protocol })
      ? JSON.stringify(normalizeSniffing(values.sniffing))
      : '',
    tag: values.tag ?? '',
    shareAddrStrategy: values.shareAddrStrategy ?? 'node',
    shareAddr: values.shareAddr ?? '',
    subSortIndex: values.subSortIndex ?? 1,
  };
  if (values.nodeId != null) payload.nodeId = values.nodeId;
  return payload;
}
