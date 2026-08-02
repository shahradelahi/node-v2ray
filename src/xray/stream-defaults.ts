const NETWORK_KEY_MAP = {
  tcp: 'tcpSettings',
  kcp: 'kcpSettings',
  ws: 'wsSettings',
  grpc: 'grpcSettings',
  httpupgrade: 'httpupgradeSettings',
  xhttp: 'xhttpSettings',
  hysteria: 'hysteriaSettings',
} as const;

/**
 * Returns default TCP stream settings.
 */
export function getTcpDefault(): Record<string, any> {
  return { header: { type: 'none' } };
}

/**
 * Returns default mKCP stream settings.
 */
export function getKcpDefault(): Record<string, any> {
  return {
    mtu: 1350,
    tti: 20,
    uplinkCapacity: 5,
    downlinkCapacity: 20,
    cwndMultiplier: 1,
    maxSendingWindow: 2097152,
  };
}

/**
 * Returns default WebSocket stream settings.
 */
export function getWsDefault(): Record<string, any> {
  return {
    path: '/',
    host: '',
    headers: {},
    heartbeatPeriod: 0,
  };
}

/**
 * Returns default gRPC stream settings.
 */
export function getGrpcDefault(): Record<string, any> {
  return {
    serviceName: '',
    authority: '',
    multiMode: false,
  };
}

/**
 * Returns default HTTPUpgrade stream settings.
 */
export function getHttpUpgradeDefault(): Record<string, any> {
  return {
    path: '/',
    host: '',
    headers: {},
  };
}

/**
 * Returns default XHTTP stream settings.
 */
export function getXHttpDefault(): Record<string, any> {
  return {
    path: '/',
    host: '',
    mode: 'auto',
    headers: {},
    xPaddingBytes: '100-1000',
  };
}

/**
 * Returns default Hysteria stream settings.
 */
export function getHysteriaDefault(): Record<string, any> {
  return {
    version: 2,
    auth: '',
    udpIdleTimeout: 60,
  };
}

/**
 * Returns default TLS stream settings.
 */
export function getTlsDefault(): Record<string, any> {
  return {
    serverName: '',
    alpn: [],
    fingerprint: '',
    echConfigList: '',
    verifyPeerCertByName: '',
    pinnedPeerCertSha256: [],
    certificates: [
      {
        useFile: true,
        certificateFile: '',
        keyFile: '',
        certificate: [],
        key: [],
        ocspStapling: 0,
        oneTimeLoading: false,
        usage: 'encipherment',
        buildChain: false,
      },
    ],
  };
}

/**
 * Returns default REALITY stream settings.
 */
export function getRealityDefault(): Record<string, any> {
  return {
    publicKey: '',
    fingerprint: 'chrome',
    serverName: '',
    shortId: '',
    spiderX: '',
    mldsa65Verify: '',
  };
}

function getDefaultSettingsForNetwork(network: string): Record<string, any> | null {
  switch (network) {
    case 'tcp':
      return getTcpDefault();
    case 'kcp':
      return getKcpDefault();
    case 'ws':
      return getWsDefault();
    case 'grpc':
      return getGrpcDefault();
    case 'httpupgrade':
      return getHttpUpgradeDefault();
    case 'xhttp':
      return getXHttpDefault();
    case 'hysteria':
      return getHysteriaDefault();
    default:
      return null;
  }
}

function getDefaultSettingsForSecurity(
  security: string
): { key: string; defaults: Record<string, any> } | null {
  switch (security) {
    case 'tls':
      return { key: 'tlsSettings', defaults: getTlsDefault() };
    case 'reality':
      return { key: 'realitySettings', defaults: getRealityDefault() };
    default:
      return null;
  }
}

/**
 * Fills missing transport and security configurations with default values.
 */
export function fillStreamDefaults(stream: Record<string, unknown>): Record<string, unknown> {
  const network = (stream['network'] as string | undefined) || 'tcp';
  const security = (stream['security'] as string | undefined) || 'none';
  const out: Record<string, unknown> = { ...stream, network, security };

  const subKey = NETWORK_KEY_MAP[network as keyof typeof NETWORK_KEY_MAP];
  if (subKey) {
    const defaults = getDefaultSettingsForNetwork(network);
    out[subKey] = { ...defaults, ...((out[subKey] as Record<string, any>) || {}) };
  }

  const sec = getDefaultSettingsForSecurity(security);
  if (sec) {
    out[sec.key] = { ...sec.defaults, ...((out[sec.key] as Record<string, any>) || {}) };
  }

  return out;
}
