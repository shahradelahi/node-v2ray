import crypto from 'node:crypto';
import { fromUint8Array } from '@se-oss/base64';
import { random, randomBase36, randomBase62, randomUuidv4 } from '@se-oss/rand';

import { Wireguard } from './utils';

interface ClientBaseSeed {
  email?: string;
  subId?: string;
  limitIp?: number;
  totalGB?: number;
  expiryTime?: number;
  enable?: boolean;
  tgId?: number;
  comment?: string;
  reset?: number;
}

interface ClientBase {
  email: string;
  limitIp: number;
  totalGB: number;
  expiryTime: number;
  enable: boolean;
  tgId: number;
  subId: string;
  comment: string;
  reset: number;
}

function clientBase(seed: ClientBaseSeed = {}): ClientBase {
  return {
    email: seed['email'] ?? randomBase36(10),
    limitIp: seed['limitIp'] ?? 0,
    totalGB: seed['totalGB'] ?? 0,
    expiryTime: seed['expiryTime'] ?? 0,
    enable: seed['enable'] ?? true,
    tgId: seed['tgId'] ?? 0,
    subId: seed['subId'] ?? randomBase36(16),
    comment: seed['comment'] ?? '',
    reset: seed['reset'] ?? 0,
  };
}

export interface VlessClientSeed extends ClientBaseSeed {
  id?: string;
  flow?: string;
}

/**
 * Creates a default VLESS client object with randomized ID and base settings.
 */
export function createDefaultVlessClient(seed: VlessClientSeed = {}): any {
  return {
    id: seed['id'] ?? randomUuidv4(),
    flow: seed['flow'] ?? '',
    ...clientBase(seed),
  };
}

export interface VmessClientSeed extends ClientBaseSeed {
  id?: string;
  security?: string;
}

/**
 * Creates a default VMess client object with randomized ID and security settings.
 */
export function createDefaultVmessClient(seed: VmessClientSeed = {}): any {
  return {
    id: seed['id'] ?? randomUuidv4(),
    security: seed['security'] ?? 'auto',
    alterId: 0,
    ...clientBase(seed),
  };
}

export interface TrojanClientSeed extends ClientBaseSeed {
  password?: string;
}

/**
 * Creates a default Trojan client object with a randomized password.
 */
export function createDefaultTrojanClient(seed: TrojanClientSeed = {}): any {
  return {
    password: seed['password'] ?? randomBase62(10),
    ...clientBase(seed),
  };
}

export interface ShadowsocksClientSeed extends ClientBaseSeed {
  method?: string;
  password?: string;
  ssMethod?: string;
}

function randomShadowsocksPassword(method: string): string {
  const len = method.includes('256') ? 32 : 16;
  return fromUint8Array(crypto.randomBytes(len));
}

/**
 * Creates a default Shadowsocks client object with a randomized password.
 */
export function createDefaultShadowsocksClient(seed: ShadowsocksClientSeed = {}): any {
  const method = seed['method'] ?? '';
  const password =
    seed['password'] ?? randomShadowsocksPassword(seed['ssMethod'] ?? '2022-blake3-aes-256-gcm');
  return {
    method,
    password,
    ...clientBase(seed),
  };
}

export interface HysteriaClientSeed extends ClientBaseSeed {
  auth?: string;
}

/**
 * Creates a default Hysteria client object with a randomized auth credential.
 */
export function createDefaultHysteriaClient(seed: HysteriaClientSeed = {}): any {
  return {
    auth: seed['auth'] ?? randomBase62(10),
    ...clientBase(seed),
  };
}

/**
 * Creates default VLESS inbound configurations.
 */
export function createDefaultVlessInboundSettings(): any {
  return {
    clients: [],
    decryption: 'none',
    encryption: 'none',
    fallbacks: [],
  };
}

/**
 * Creates default VMess inbound configurations.
 */
export function createDefaultVmessInboundSettings(): any {
  return { clients: [] };
}

/**
 * Creates default Trojan inbound configurations.
 */
export function createDefaultTrojanInboundSettings(): any {
  return { clients: [], fallbacks: [] };
}

export interface ShadowsocksInboundSeed {
  method?: string;
  password?: string;
  network?: string;
  ivCheck?: boolean;
}

/**
 * Creates default Shadowsocks inbound configurations.
 */
export function createDefaultShadowsocksInboundSettings(seed: ShadowsocksInboundSeed = {}): any {
  const method = seed['method'] ?? '2022-blake3-aes-256-gcm';
  return {
    method,
    password: seed['password'] ?? randomShadowsocksPassword(method),
    network: seed['network'] ?? 'tcp,udp',
    clients: [],
    ivCheck: seed['ivCheck'] ?? false,
  };
}

export interface HysteriaInboundSeed {
  version?: number;
}

/**
 * Creates default Hysteria inbound configurations.
 */
export function createDefaultHysteriaInboundSettings(seed: HysteriaInboundSeed = {}): any {
  return {
    version: seed['version'] ?? 2,
    clients: [],
  };
}

/**
 * Creates default HTTP inbound configurations.
 */
export function createDefaultHttpInboundSettings(): any {
  return {
    accounts: [{ user: randomBase36(8), pass: randomBase36(12) }],
    allowTransparent: false,
  };
}

/**
 * Creates default Mixed inbound configurations.
 */
export function createDefaultMixedInboundSettings(): any {
  return {
    auth: 'password',
    accounts: [{ user: randomBase36(8), pass: randomBase36(12) }],
    udp: false,
    ip: '127.0.0.1',
  };
}

function domainToHex(domain: string): string {
  return Array.from(new TextEncoder().encode(domain))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generates a randomized MTProto secret with an appended fake TLS domain hex.
 */
export function generateMtprotoSecret(domain: string): string {
  return `ee${random('0123456789abcdef', 32)}${domainToHex(domain)}`;
}

/**
 * Normalizes or creates an MTProto secret with a specified fake TLS domain hex.
 */
export function mtprotoSecretForDomain(currentSecret: string, domain: string): string {
  let body = currentSecret;
  if (body.startsWith('ee') || body.startsWith('dd')) {
    body = body.slice(2);
  }
  const middle = /^[0-9a-f]{32}/i.test(body) ? body.slice(0, 32) : random('0123456789abcdef', 32);
  return `ee${middle}${domainToHex(domain)}`;
}

/**
 * Creates default MTProto inbound configurations.
 */
export function createDefaultMtprotoInboundSettings(): any {
  const fakeTlsDomain = 'www.cloudflare.com';
  return {
    fakeTlsDomain,
    secret: generateMtprotoSecret(fakeTlsDomain),
  };
}

/**
 * Creates default Tunnel inbound configurations.
 */
export function createDefaultTunnelInboundSettings(): any {
  return {
    portMap: {},
    allowedNetwork: 'tcp,udp',
    followRedirect: false,
  };
}

/**
 * Creates default Tun inbound configurations.
 */
export function createDefaultTunInboundSettings(): any {
  return {
    name: 'xray0',
    mtu: 1500,
    gateway: [],
    dns: [],
    userLevel: 0,
    autoSystemRoutingTable: [],
    autoOutboundsInterface: 'auto',
  };
}

export interface WireguardInboundSeed {
  mtu?: number;
  secretKey?: string;
  noKernelTun?: boolean;
}

/**
 * Creates default WireGuard inbound configurations.
 */
export function createDefaultWireguardInboundSettings(seed: WireguardInboundSeed = {}): any {
  return {
    mtu: seed['mtu'] ?? 1420,
    secretKey: seed['secretKey'] ?? Wireguard.generateKeypair()['privateKey'],
    peers: [],
    clients: [],
    noKernelTun: seed['noKernelTun'] ?? false,
  };
}

/**
 * Dynamically resolves and returns default inbound configurations based on protocol.
 * @param protocol Target protocol.
 * @example
 * ```ts
 * const settings = createDefaultInboundSettings('vless');
 * console.log(settings.clients); // []
 * ```
 */
export function createDefaultInboundSettings(protocol: string): any | null {
  switch (protocol) {
    case 'vless':
      return createDefaultVlessInboundSettings();
    case 'vmess':
      return createDefaultVmessInboundSettings();
    case 'trojan':
      return createDefaultTrojanInboundSettings();
    case 'shadowsocks':
      return createDefaultShadowsocksInboundSettings();
    case 'hysteria':
      return createDefaultHysteriaInboundSettings();
    case 'http':
      return createDefaultHttpInboundSettings();
    case 'mixed':
      return createDefaultMixedInboundSettings();
    case 'tunnel':
      return createDefaultTunnelInboundSettings();
    case 'tun':
      return createDefaultTunInboundSettings();
    case 'wireguard':
      return createDefaultWireguardInboundSettings();
    case 'mtproto':
      return createDefaultMtprotoInboundSettings();
    default:
      return null;
  }
}
