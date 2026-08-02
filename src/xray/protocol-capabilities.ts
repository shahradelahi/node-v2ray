const TLS_ELIGIBLE_PROTOCOLS = ['vmess', 'vless', 'trojan', 'shadowsocks'];
const TLS_NETWORKS = ['tcp', 'ws', 'http', 'grpc', 'httpupgrade', 'xhttp'];
const REALITY_ELIGIBLE_PROTOCOLS = ['vless', 'trojan'];
const REALITY_NETWORKS = ['tcp', 'http', 'grpc', 'xhttp'];
const STREAM_PROTOCOLS = [
  'vmess',
  'vless',
  'trojan',
  'shadowsocks',
  'hysteria',
  'wireguard',
  'tunnel',
];
const VISION_FLOW = 'xtls-rprx-vision';
const SS_2022_PREFIX = '2022';
const SS_BLAKE3_CHACHA20 = '2022-blake3-chacha20-poly1305';

export interface CapabilityProtocolSlice {
  protocol: string;
  settings?: { encryption?: string; decryption?: string };
  streamSettings?: { network?: string; security?: string };
}

export interface CapabilityVlessSlice extends CapabilityProtocolSlice {
  settings?: { encryption?: string; decryption?: string; clients?: { flow?: string }[] };
}

export interface CapabilityShadowsocksSlice extends CapabilityProtocolSlice {
  settings?: { encryption?: string; method?: string };
}

/**
 * Checks if the protocol configuration supports TLS security.
 */
export function canEnableTls(values: CapabilityProtocolSlice): boolean {
  if (values.protocol === 'hysteria') return true;
  if (!TLS_ELIGIBLE_PROTOCOLS.includes(values.protocol)) return false;
  return TLS_NETWORKS.includes(values.streamSettings?.network ?? '');
}

/**
 * Checks if the protocol configuration supports REALITY security.
 */
export function canEnableReality(values: CapabilityProtocolSlice): boolean {
  if (!REALITY_ELIGIBLE_PROTOCOLS.includes(values.protocol)) return false;
  return REALITY_NETWORKS.includes(values.streamSettings?.network ?? '');
}

function hasVlessEncryption(settings: CapabilityProtocolSlice['settings']): boolean {
  const isSet = (v?: string) => v != null && v !== '' && v !== 'none';
  return isSet(settings?.encryption) || isSet(settings?.decryption);
}

/**
 * Checks if the VLESS configuration supports flow control under TLS or REALITY.
 */
export function canEnableTlsFlow(values: CapabilityProtocolSlice): boolean {
  if (values.protocol !== 'vless') return false;
  const network = values.streamSettings?.network;
  const security = values.streamSettings?.security;

  // Classic XTLS Vision: raw TCP carried over TLS or REALITY.
  if (network === 'tcp' && (security === 'tls' || security === 'reality')) return true;

  // vlessenc carries Vision over XHTTP without transport TLS.
  if (network === 'xhttp' && hasVlessEncryption(values.settings)) return true;

  return false;
}

/**
 * Checks if the protocol supports stream transport settings.
 */
export function canEnableStream(values: { protocol: string }): boolean {
  return STREAM_PROTOCOLS.includes(values.protocol);
}

/**
 * Checks if the protocol supports traffic sniffing options.
 */
export function canEnableSniffing(values: { protocol: string }): boolean {
  return values.protocol !== 'mtproto';
}

/**
 * Checks if the VLESS configuration requires Vision seed optimization.
 */
export function canEnableVisionSeed(values: CapabilityVlessSlice): boolean {
  if (!canEnableTlsFlow(values)) return false;
  const clients = values.settings?.clients;
  if (!Array.isArray(clients)) return false;
  return clients.some((c) => c?.flow === VISION_FLOW);
}

/**
 * Checks if the Shadowsocks configuration supports multiple clients.
 */
export function isSSMultiUser(values: CapabilityShadowsocksSlice): boolean {
  const method = values.protocol === 'shadowsocks' ? (values.settings?.method ?? '') : '';
  return method !== SS_BLAKE3_CHACHA20;
}

/**
 * Checks if the Shadowsocks method belongs to the 2022 standard specification.
 */
export function isSS2022(values: CapabilityShadowsocksSlice): boolean {
  const method = values.protocol === 'shadowsocks' ? (values.settings?.method ?? '') : '';
  return method.substring(0, 4) === SS_2022_PREFIX;
}
