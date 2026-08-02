import { Wireguard } from './utils';

/**
 * Creates default Freedom outbound configurations.
 */
export function createDefaultFreedomOutboundSettings(): Record<string, any> {
  return {};
}

/**
 * Creates default Blackhole outbound configurations.
 */
export function createDefaultBlackholeOutboundSettings(): Record<string, any> {
  return {};
}

/**
 * Creates default Loopback outbound configurations.
 */
export function createDefaultLoopbackOutboundSettings(): Record<string, any> {
  return { inboundTag: '' };
}

/**
 * Creates default DNS outbound configurations.
 */
export function createDefaultDNSOutboundSettings(): Record<string, any> {
  return {
    rewriteNetwork: '',
    rewriteAddress: '',
    rewritePort: 53,
    userLevel: 0,
    rules: [],
  };
}

/**
 * Creates default VMess outbound configurations.
 */
export function createDefaultVmessOutboundSettings(): Record<string, any> {
  return {
    vnext: [
      {
        address: '',
        port: 443,
        users: [{ id: '', security: 'auto' }],
      },
    ],
  };
}

/**
 * Creates default VLESS outbound configurations.
 */
export function createDefaultVlessOutboundSettings(): Record<string, any> {
  return {
    address: '',
    port: 443,
    id: '',
    flow: '',
    encryption: 'none',
  };
}

/**
 * Creates default Trojan outbound configurations.
 */
export function createDefaultTrojanOutboundSettings(): Record<string, any> {
  return {
    servers: [{ address: '', port: 443, password: '' }],
  };
}

/**
 * Creates default Shadowsocks outbound configurations.
 */
export function createDefaultShadowsocksOutboundSettings(): Record<string, any> {
  return {
    servers: [
      {
        address: '',
        port: 443,
        password: '',
        method: '2022-blake3-aes-128-gcm',
      },
    ],
  };
}

/**
 * Creates default Socks outbound configurations.
 */
export function createDefaultSocksOutboundSettings(): Record<string, any> {
  return {
    servers: [{ address: '', port: 1080, users: [] }],
  };
}

/**
 * Creates default HTTP outbound configurations.
 */
export function createDefaultHttpOutboundSettings(): Record<string, any> {
  return {
    servers: [{ address: '', port: 8080, users: [] }],
  };
}

interface WireguardOutboundSeed {
  secretKey?: string;
}

/**
 * Creates default Wireguard outbound configurations.
 */
export function createDefaultWireguardOutboundSettings(
  seed: WireguardOutboundSeed = {}
): Record<string, any> {
  const secretKey = seed.secretKey ?? Wireguard.generateKeypair().privateKey;
  return {
    mtu: 1420,
    secretKey,
    address: [],
    peers: [
      {
        publicKey: '',
        allowedIPs: ['0.0.0.0/0', '::/0'],
        endpoint: '',
      },
    ],
    noKernelTun: false,
  };
}

/**
 * Creates default Hysteria outbound configurations.
 */
export function createDefaultHysteriaOutboundSettings(): Record<string, any> {
  return { address: '', port: 443, version: 2 };
}

/**
 * Generates default outbound configuration settings based on a given protocol.
 *
 * @example
 * ```ts
 * const settings = createDefaultOutboundSettings('vless');
 * ```
 */
export function createDefaultOutboundSettings(protocol: string): Record<string, any> | null {
  switch (protocol) {
    case 'freedom':
      return createDefaultFreedomOutboundSettings();
    case 'blackhole':
      return createDefaultBlackholeOutboundSettings();
    case 'dns':
      return createDefaultDNSOutboundSettings();
    case 'vmess':
      return createDefaultVmessOutboundSettings();
    case 'vless':
      return createDefaultVlessOutboundSettings();
    case 'trojan':
      return createDefaultTrojanOutboundSettings();
    case 'shadowsocks':
      return createDefaultShadowsocksOutboundSettings();
    case 'socks':
      return createDefaultSocksOutboundSettings();
    case 'http':
      return createDefaultHttpOutboundSettings();
    case 'wireguard':
      return createDefaultWireguardOutboundSettings();
    case 'hysteria':
      return createDefaultHysteriaOutboundSettings();
    case 'loopback':
      return createDefaultLoopbackOutboundSettings();
    default:
      return null;
  }
}
