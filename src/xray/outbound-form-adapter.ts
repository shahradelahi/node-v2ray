import { normalizeStreamSettingsForWire } from './stream-wire-normalize';
import { Wireguard } from './utils';

function asObject(value: unknown): any {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as any) : {};
}

function asArray(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  }
  return fallback;
}

function asBool(value: unknown): boolean {
  return value === true;
}

function asPort(value: unknown, fallback: number): number {
  const n = asNumber(value, fallback);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return fallback;
  return n;
}

const SNIFFING_DEST_VALUES = ['http', 'tls', 'quic', 'fakedns'] as const;

const SNIFFING_DEFAULT = {
  enabled: false,
  destOverride: [...SNIFFING_DEST_VALUES],
  metadataOnly: false,
  routeOnly: false,
  ipsExcluded: [],
  domainsExcluded: [],
};

function sniffingFromWire(raw: unknown): any {
  const r = asObject(raw);
  const dest = asArray(r.destOverride)
    .map((x) => asString(x))
    .filter((x): x is any => SNIFFING_DEST_VALUES.includes(x as any));
  return {
    enabled: asBool(r.enabled),
    destOverride: dest.length > 0 ? dest : [...SNIFFING_DEST_VALUES],
    metadataOnly: asBool(r.metadataOnly),
    routeOnly: asBool(r.routeOnly),
    ipsExcluded: asArray(r.ipsExcluded).map((x) => asString(x)),
    domainsExcluded: asArray(r.domainsExcluded).map((x) => asString(x)),
  };
}

function vmessFromWire(raw: any): any {
  const vnext = asArray(raw.vnext);
  const v = asObject(vnext[0]);
  const u = asObject(asArray(v.users)[0]);
  return {
    address: asString(v.address),
    port: asPort(v.port, 443),
    id: asString(u.id),
    security: ((): string => {
      const s = asString(u.security);
      const allowed = ['aes-128-gcm', 'chacha20-poly1305', 'auto', 'none', 'zero'];
      return allowed.includes(s) ? s : 'auto';
    })(),
  };
}

function vlessFromWire(raw: any): any {
  let address = asString(raw.address);
  let port = asPort(raw.port, 443);
  let id = asString(raw.id);
  let flow = asString(raw.flow);
  let encryption = asString(raw.encryption, 'none');
  const vnext = asArray(raw.vnext);
  if (vnext.length > 0) {
    const v = asObject(vnext[0]);
    const u = asObject(asArray(v.users)[0]);
    address = asString(v.address);
    port = asPort(v.port, 443);
    id = asString(u.id);
    flow = asString(u.flow);
    encryption = asString(u.encryption, 'none');
  }
  const reverse = asObject(raw.reverse);
  const reverseTag = asString(reverse.tag);
  const reverseSniffing = reverseTag ? sniffingFromWire(reverse.sniffing) : SNIFFING_DEFAULT;
  const savedSeed = asArray(raw.testseed);
  const testseed =
    savedSeed.length === 4 && savedSeed.every((n) => Number.isInteger(n) && (n as number) > 0)
      ? (savedSeed as number[])
      : [900, 500, 900, 256];
  return {
    address,
    port,
    id,
    flow,
    encryption: encryption || 'none',
    reverseTag,
    reverseSniffing,
    testpre: asNumber(raw.testpre, 0),
    testseed,
  };
}

function trojanFromWire(raw: any): any {
  const s = asObject(asArray(raw.servers)[0]);
  return {
    address: asString(s.address),
    port: asPort(s.port, 443),
    password: asString(s.password),
  };
}

function shadowsocksFromWire(raw: any): any {
  const s = asObject(asArray(raw.servers)[0]);
  return {
    address: asString(s.address),
    port: asPort(s.port, 443),
    password: asString(s.password),
    method: asString(s.method, '2022-blake3-aes-128-gcm'),
    uot: asBool(s.uot),
    UoTVersion: asNumber(s.UoTVersion, 1),
  };
}

function simpleAuthFromWire(raw: any, defaultPort: number): any {
  const s = asObject(asArray(raw.servers)[0]);
  const u = asObject(asArray(s.users)[0]);
  return {
    address: asString(s.address),
    port: asPort(s.port, defaultPort),
    user: asString(u.user),
    pass: asString(u.pass),
  };
}

function stringRecordFromWire(raw: unknown): Record<string, string> {
  const obj = asObject(raw);
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function httpFromWire(raw: any): any {
  return {
    ...simpleAuthFromWire(raw, 8080),
    headers: stringRecordFromWire(raw.headers),
  };
}

function wireguardFromWire(raw: any): any {
  const secretKey = asString(raw.secretKey);
  const pubKey = secretKey.length > 0 ? Wireguard.generateKeypair(secretKey).publicKey : '';
  const addressArr = asArray(raw.address).map((x) =>
    typeof x === 'number' ? String(x) : asString(x)
  );
  const reservedArr = asArray(raw.reserved).map((x) =>
    typeof x === 'number' ? String(x) : asString(x)
  );
  const peers: any[] = asArray(raw.peers).map((p) => {
    const pp = asObject(p);
    const allowed = asArray(pp.allowedIPs).map((x) => asString(x));
    return {
      publicKey: asString(pp.publicKey),
      psk: asString(pp.preSharedKey),
      allowedIPs: allowed.length > 0 ? allowed : ['0.0.0.0/0', '::/0'],
      endpoint: asString(pp.endpoint),
      keepAlive: asNumber(pp.keepAlive, 0),
    };
  });
  return {
    mtu: asNumber(raw.mtu, 1420),
    secretKey,
    pubKey,
    address: addressArr.join(','),
    domainStrategy: ((): string => {
      const allowed = ['ForceIP', 'ForceIPv4', 'ForceIPv4v6', 'ForceIPv6', 'ForceIPv6v4'];
      const s = asString(raw.domainStrategy);
      return allowed.includes(s) ? s : '';
    })(),
    reserved: reservedArr.join(','),
    peers,
    noKernelTun: asBool(raw.noKernelTun),
  };
}

function hysteriaFromWire(raw: any): any {
  return {
    address: asString(raw.address),
    port: asPort(raw.port, 443),
    version: 2,
  };
}

function freedomFromWire(raw: any): any {
  const fragment = asObject(raw.fragment);
  const noises = asArray(raw.noises).map((n) => {
    const nn = asObject(n);
    return {
      type: asString(nn.type, 'rand'),
      packet: asString(nn.packet, '10-20'),
      delay: asString(nn.delay, '10-16'),
      applyTo: asString(nn.applyTo, 'ip'),
    };
  });
  const finalRulesRaw = asArray(raw.finalRules);
  const finalRules: any[] = finalRulesRaw.map((r) => {
    const rr = asObject(r);
    const network = Array.isArray(rr.network)
      ? rr.network.map((x: any) => asString(x)).join(',')
      : asString(rr.network);
    return {
      action: asString(rr.action, 'block') === 'allow' ? 'allow' : 'block',
      network,
      port: asString(rr.port),
      ip: asArray(rr.ip).map((x) => asString(x)),
      blockDelay: asString(rr.blockDelay),
    };
  });
  if (finalRules.length === 0) {
    const ipsBlocked = asArray(raw.ipsBlocked).map((x) => asString(x));
    if (ipsBlocked.length > 0) {
      finalRules.push({ action: 'block', network: '', port: '', ip: ipsBlocked, blockDelay: '' });
    }
  }
  const wireHasFragment =
    raw.fragment != null && typeof raw.fragment === 'object' && Object.keys(fragment).length > 0;
  return {
    domainStrategy: ((): string => {
      const allowed = [
        'AsIs',
        'UseIP',
        'UseIPv4',
        'UseIPv6',
        'UseIPv6v4',
        'UseIPv4v6',
        'ForceIP',
        'ForceIPv6v4',
        'ForceIPv6',
        'ForceIPv4v6',
        'ForceIPv4',
      ];
      const s = asString(raw.domainStrategy);
      return allowed.includes(s) ? s : '';
    })(),
    redirect: asString(raw.redirect),
    userLevel: asNumber(raw.userLevel, 0),
    proxyProtocol: ((): number => {
      const n = asNumber(raw.proxyProtocol, 0);
      return n === 1 || n === 2 ? n : 0;
    })(),
    fragment: wireHasFragment
      ? {
          packets: asString(fragment.packets, '1-3'),
          length: asString(fragment.length),
          interval: asString(fragment.interval),
          maxSplit: asString(fragment.maxSplit),
        }
      : { packets: '', length: '', interval: '', maxSplit: '' },
    noises,
    finalRules,
  };
}

function blackholeFromWire(raw: any) {
  const response = asObject(raw.response);
  const t = asString(response.type);
  return { type: (t === 'none' || t === 'http' ? t : '') as '' | 'none' | 'http' };
}

function dnsRuleFromWire(raw: unknown): any {
  const r = asObject(raw);
  const rawQType = r.qType ?? r.qtype;
  const qType = Array.isArray(rawQType)
    ? rawQType.map((x) => String(x)).join(',')
    : typeof rawQType === 'number'
      ? String(rawQType)
      : asString(rawQType);
  const domain = Array.isArray(r.domain)
    ? r.domain.map((x: any) => asString(x)).join(',')
    : asString(r.domain);
  const action = asString(r.action, 'direct');
  const validAction = ['direct', 'drop', 'return', 'hijack'].includes(action) ? action : 'direct';
  return { action: validAction, qType, domain, rCode: asNumber(r.rCode, 0) };
}

function dnsFromWire(raw: any): any {
  const rules = asArray(raw.rules).map(dnsRuleFromWire);
  return {
    rewriteNetwork: ((): string => {
      const s = asString(raw.rewriteNetwork ?? raw.network);
      return s === 'udp' || s === 'tcp' ? s : '';
    })(),
    rewriteAddress: asString(raw.rewriteAddress ?? raw.address),
    rewritePort: asPort(raw.rewritePort ?? raw.port, 53),
    userLevel: asNumber(raw.userLevel, 0),
    rules,
  };
}

function loopbackFromWire(raw: any): any {
  return {
    inboundTag: asString(raw.inboundTag),
    sniffing: sniffingFromWire(raw.sniffing),
  };
}

function muxFromWire(raw: unknown): any {
  const m = asObject(raw);
  return {
    enabled: asBool(m.enabled),
    concurrency: asNumber(m.concurrency, 8),
    xudpConcurrency: asNumber(m.xudpConcurrency, 16),
    xudpProxyUDP443: ((): string => {
      const s = asString(m.xudpProxyUDP443, 'reject');
      return ['reject', 'allow', 'skip'].includes(s) ? s : 'reject';
    })(),
  };
}

export interface RawOutboundRow {
  tag?: string;
  protocol?: string;
  sendThrough?: string;
  settings?: unknown;
  streamSettings?: unknown;
  mux?: unknown;
}

const XMUX_DEFAULTS = {
  maxConnections: 0,
  maxConcurrency: '16-32',
  concurrency: 8,
};

function hydrateStreamForm(stream: any): any {
  const next = { ...stream };
  const xh = next.xhttpSettings;
  if (xh && typeof xh === 'object' && !Array.isArray(xh)) {
    const xhttp = { ...(xh as any) };
    const xmux = xhttp.xmux;
    if (xmux && typeof xmux === 'object' && !Array.isArray(xmux)) {
      xhttp.enableXmux = true;
      xhttp.xmux = { ...XMUX_DEFAULTS, ...(xmux as any) };
    }
    next.xhttpSettings = xhttp;
  }
  return next;
}

/**
 * Converts raw outbound configurations into form input values.
 */
export function rawOutboundToFormValues(raw: RawOutboundRow): any {
  const protocol = asString(raw.protocol, 'vless');
  const settings = asObject(raw.settings);
  const tag = asString(raw.tag);
  const sendThrough = asString(raw.sendThrough);
  const mux = muxFromWire(raw.mux);
  const hasStream =
    raw.streamSettings &&
    typeof raw.streamSettings === 'object' &&
    Object.keys(raw.streamSettings as any).length > 0;
  const streamSettings = hasStream ? hydrateStreamForm(raw.streamSettings as any) : undefined;

  let typed: any;
  switch (protocol) {
    case 'vmess':
      typed = { protocol: 'vmess', settings: vmessFromWire(settings) };
      break;
    case 'vless':
      typed = { protocol: 'vless', settings: vlessFromWire(settings) };
      break;
    case 'trojan':
      typed = { protocol: 'trojan', settings: trojanFromWire(settings) };
      break;
    case 'shadowsocks':
      typed = { protocol: 'shadowsocks', settings: shadowsocksFromWire(settings) };
      break;
    case 'socks':
      typed = { protocol: 'socks', settings: simpleAuthFromWire(settings, 1080) };
      break;
    case 'http':
      typed = { protocol: 'http', settings: httpFromWire(settings) };
      break;
    case 'wireguard':
      typed = { protocol: 'wireguard', settings: wireguardFromWire(settings) };
      break;
    case 'hysteria':
      typed = { protocol: 'hysteria', settings: hysteriaFromWire(settings) };
      break;
    case 'freedom':
      typed = { protocol: 'freedom', settings: freedomFromWire(settings) };
      break;
    case 'blackhole':
      typed = { protocol: 'blackhole', settings: blackholeFromWire(settings) };
      break;
    case 'dns':
      typed = { protocol: 'dns', settings: dnsFromWire(settings) };
      break;
    case 'loopback':
      typed = { protocol: 'loopback', settings: loopbackFromWire(settings) };
      break;
    default:
      typed = { protocol: 'vless', settings: vlessFromWire(settings) };
  }

  return {
    ...typed,
    tag,
    sendThrough,
    mux,
    streamSettings,
  };
}

const MUX_PROTOCOLS = new Set(['vmess', 'vless', 'trojan', 'shadowsocks', 'http', 'socks']);
const STREAM_PROTOCOLS = new Set(['vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria']);

function dropEmptyStrings(obj: any): any {
  const out: any = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === '') continue;
    out[k] = v;
  }
  return out;
}

function stripUiOnlyStreamFields(stream: unknown): any {
  const next = { ...(stream as any) };
  const xh = next.xhttpSettings;
  if (xh && typeof xh === 'object') {
    const cleaned = { ...(xh as any) };
    const xmuxEnabled = cleaned.enableXmux === true;
    delete cleaned.enableXmux;
    if (!xmuxEnabled) delete cleaned.xmux;
    next.xhttpSettings = dropEmptyStrings(cleaned);
  }
  return normalizeStreamSettingsForWire(next, { side: 'outbound' }) as any;
}

function muxAllowed(values: any): boolean {
  if (!MUX_PROTOCOLS.has(values.protocol)) return false;
  const flow = values.protocol === 'vless' ? (values.settings as any).flow : '';
  if (flow) return false;
  const network =
    values.streamSettings && 'network' in values.streamSettings
      ? values.streamSettings.network
      : undefined;
  if (network === 'xhttp') return false;
  return true;
}

function vmessToWire(s: any) {
  return {
    vnext: [
      {
        address: s.address,
        port: s.port,
        users: [{ id: s.id, security: s.security }],
      },
    ],
  };
}

function vlessToWire(s: any) {
  const result: any = {
    address: s.address,
    port: s.port,
    id: s.id,
    flow: s.flow,
    encryption: s.encryption || 'none',
  };
  if (s.reverseTag) {
    const sn = sniffingFromWire(s.reverseSniffing);
    const defaultSn = sniffingFromWire(SNIFFING_DEFAULT);
    result.reverse = {
      tag: s.reverseTag,
      sniffing: JSON.stringify(sn) === JSON.stringify(defaultSn) ? {} : sn,
    };
  }
  if (s.flow === 'xtls-rprx-vision') {
    if (s.testpre > 0) result.testpre = s.testpre;
    if (
      s.testseed &&
      s.testseed.length === 4 &&
      s.testseed.every((v: any) => Number.isInteger(v) && v > 0)
    ) {
      result.testseed = s.testseed;
    }
  }
  return result;
}

function trojanToWire(s: any) {
  return { servers: [{ address: s.address, port: s.port, password: s.password }] };
}

function shadowsocksToWire(s: any) {
  return {
    servers: [
      {
        address: s.address,
        port: s.port,
        password: s.password,
        method: s.method,
        uot: s.uot,
        UoTVersion: s.UoTVersion,
      },
    ],
  };
}

function simpleAuthToWire(s: any) {
  return {
    servers: [
      {
        address: s.address,
        port: s.port,
        users: s.user ? [{ user: s.user, pass: s.pass }] : [],
      },
    ],
  };
}

function httpToWire(s: any): any {
  const wire: any = simpleAuthToWire(s);
  if (s.headers && Object.keys(s.headers).length > 0) {
    wire.headers = s.headers;
  }
  return wire;
}

function wireguardToWire(s: any) {
  return {
    mtu: s.mtu || undefined,
    secretKey: s.secretKey,
    address: s.address
      ? s.address
          .split(',')
          .map((x: any) => x.trim())
          .filter(Boolean)
      : [],
    domainStrategy: s.domainStrategy || undefined,
    reserved: s.reserved
      ? s.reserved
          .split(',')
          .map((x: any) => Number(x.trim()))
          .filter((n: any) => Number.isFinite(n))
      : undefined,
    peers: s.peers.map((p: any) => ({
      publicKey: p.publicKey,
      preSharedKey: p.psk.length > 0 ? p.psk : undefined,
      allowedIPs: p.allowedIPs.length > 0 ? p.allowedIPs : undefined,
      endpoint: p.endpoint,
      keepAlive: p.keepAlive || undefined,
    })),
    noKernelTun: s.noKernelTun,
  };
}

function hysteriaToWire(s: any) {
  return { address: s.address, port: s.port, version: s.version };
}

function freedomToWire(s: any) {
  const fragment: any = s.fragment ?? {};
  const fragmentEntries = Object.entries(fragment).filter(([, v]) => v !== '' && v != null);
  const fragmentEnabled = !!fragment.length || !!fragment.interval || !!fragment.maxSplit;
  return {
    domainStrategy: s.domainStrategy || undefined,
    redirect: s.redirect || undefined,
    userLevel: s.userLevel || undefined,
    proxyProtocol: s.proxyProtocol || undefined,
    fragment: fragmentEnabled ? Object.fromEntries(fragmentEntries) : undefined,
    noises: s.noises && s.noises.length > 0 ? s.noises : undefined,
    finalRules:
      s.finalRules && s.finalRules.length > 0
        ? s.finalRules.map((r: any) => ({
            action: r.action,
            network: r.network || undefined,
            port: r.port || undefined,
            ip: r.ip.length > 0 ? r.ip : undefined,
            blockDelay: r.action === 'block' && r.blockDelay ? r.blockDelay : undefined,
          }))
        : undefined,
  };
}

function blackholeToWire(s: any) {
  return { response: s.type ? { type: s.type } : undefined };
}

function dnsRuleToWire(r: any) {
  const action = ['direct', 'drop', 'return', 'hijack'].includes(r.action) ? r.action : 'direct';
  const result: any = { action };
  const qType = r.qType.trim();
  if (qType) {
    result.qType = /^\d+$/.test(qType) ? Number(qType) : qType;
  }
  const domains = r.domain
    .split(',')
    .map((d: any) => d.trim())
    .filter(Boolean);
  if (domains.length > 0) result.domain = domains;
  if (r.rCode > 0) result.rCode = r.rCode;
  return result;
}

function dnsToWire(s: any) {
  const result: any = {};
  if (s.rewriteNetwork) result.rewriteNetwork = s.rewriteNetwork;
  if (s.rewriteAddress) result.rewriteAddress = s.rewriteAddress;
  if (s.rewritePort) result.rewritePort = s.rewritePort;
  if (s.userLevel) result.userLevel = s.userLevel;
  if (s.rules && s.rules.length > 0) result.rules = s.rules.map(dnsRuleToWire);
  return result;
}

function loopbackToWire(s: any) {
  const result: any = { inboundTag: s.inboundTag || undefined };
  if (s.sniffing?.enabled) {
    result.sniffing = sniffingFromWire(s.sniffing);
  }
  return result;
}

/**
 * Converts form input values into a normalized outbound wire payload.
 */
export function formValuesToWirePayload(values: any): any {
  let settings: any;
  switch (values.protocol) {
    case 'vmess':
      settings = vmessToWire(values.settings);
      break;
    case 'vless':
      settings = vlessToWire(values.settings);
      break;
    case 'trojan':
      settings = trojanToWire(values.settings);
      break;
    case 'shadowsocks':
      settings = shadowsocksToWire(values.settings);
      break;
    case 'socks':
      settings = simpleAuthToWire(values.settings);
      break;
    case 'http':
      settings = httpToWire(values.settings);
      break;
    case 'wireguard':
      settings = wireguardToWire(values.settings);
      break;
    case 'hysteria':
      settings = hysteriaToWire(values.settings);
      break;
    case 'freedom':
      settings = freedomToWire(values.settings);
      break;
    case 'blackhole':
      settings = blackholeToWire(values.settings);
      break;
    case 'dns':
      settings = dnsToWire(values.settings);
      break;
    case 'loopback':
      settings = loopbackToWire(values.settings);
      break;
  }

  const result: any = {
    protocol: values.protocol,
    settings,
  };
  if (values.tag) result.tag = values.tag;

  if (values.streamSettings) {
    if (STREAM_PROTOCOLS.has(values.protocol)) {
      result.streamSettings = stripUiOnlyStreamFields(values.streamSettings);
    } else {
      const sockopt = (values.streamSettings as any).sockopt;
      if (sockopt) result.streamSettings = { sockopt };
    }
  }

  if (values.sendThrough) result.sendThrough = values.sendThrough;
  if (values.mux?.enabled && muxAllowed(values)) {
    result.mux = values.mux;
  }
  return result;
}
