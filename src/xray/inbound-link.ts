import { Base64 } from '@se-oss/base64';

import { getHeaderValue } from './headers';
import { canEnableTlsFlow } from './protocol-capabilities';
import { Wireguard } from './utils';

type ForceTls = 'same' | 'tls' | 'none';

function formatUrlHost(address: string): string {
  const bare = address.replace(/^\[|\]$/g, '');
  return bare.includes(':') ? `[${bare}]` : bare;
}

function xhttpHostFallback(xhttp: any | undefined): string {
  return getHeaderValue(xhttp?.headers, 'host');
}

function buildXhttpExtra(xhttp: any | undefined): Record<string, unknown> | null {
  if (!xhttp) return null;
  const extra: Record<string, unknown> = {};

  if (typeof xhttp.mode === 'string' && xhttp.mode.length > 0) {
    extra['mode'] = xhttp.mode;
  }

  if (typeof xhttp.xPaddingBytes === 'string' && xhttp.xPaddingBytes.length > 0) {
    extra['xPaddingBytes'] = xhttp.xPaddingBytes;
  }
  if (xhttp.xPaddingObfsMode === true) {
    extra['xPaddingObfsMode'] = true;
    for (const k of [
      'xPaddingKey',
      'xPaddingHeader',
      'xPaddingPlacement',
      'xPaddingMethod',
    ] as const) {
      const v = xhttp[k];
      if (typeof v === 'string' && v.length > 0) extra[k] = v;
    }
  }

  const stringFields = [
    'uplinkHTTPMethod',
    'sessionIDPlacement',
    'sessionIDKey',
    'sessionIDTable',
    'sessionIDLength',
    'seqPlacement',
    'seqKey',
    'uplinkDataPlacement',
    'uplinkDataKey',
    'scMaxEachPostBytes',
  ] as const;

  const coreDefaults: Partial<Record<(typeof stringFields)[number], string>> = {
    scMaxEachPostBytes: '1000000',
  };
  for (const k of stringFields) {
    const v = xhttp[k];
    if (typeof v === 'string' && v.length > 0 && v !== coreDefaults[k]) extra[k] = v;
  }

  if (xhttp.headers && Object.keys(xhttp.headers).length > 0) {
    const headersMap: Record<string, string> = {};
    for (const [name, value] of Object.entries(xhttp.headers)) {
      if (name.toLowerCase() === 'host') continue;
      headersMap[name] = value as string;
    }
    if (Object.keys(headersMap).length > 0) extra['headers'] = headersMap;
  }

  return Object.keys(extra).length > 0 ? extra : null;
}

function applyXhttpExtraToObj(xhttp: any | undefined, obj: Record<string, unknown>): void {
  if (!xhttp) return;
  if (typeof xhttp.xPaddingBytes === 'string' && xhttp.xPaddingBytes.length > 0) {
    obj['x_padding_bytes'] = xhttp.xPaddingBytes;
  }
  const extra = buildXhttpExtra(xhttp);
  if (!extra) return;
  for (const [k, v] of Object.entries(extra)) obj[k] = v;
}

function hasShareableFinalMaskValue(value: unknown): boolean {
  if (value == null) return false;
  if (Array.isArray(value)) return value.some(hasShareableFinalMaskValue);
  if (typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).some(hasShareableFinalMaskValue);
  }
  if (typeof value === 'string') return value.length > 0;
  return true;
}

function serializeFinalMask(finalmask: any | undefined): string {
  if (!finalmask) return '';
  return hasShareableFinalMaskValue(finalmask) ? JSON.stringify(finalmask) : '';
}

function applyFinalMaskToObj(finalmask: any | undefined, obj: Record<string, unknown>): void {
  const payload = serializeFinalMask(finalmask);
  if (payload.length > 0) obj['fm'] = payload;
}

function externalProxyAlpn(value: any): string {
  if (Array.isArray(value)) return value.filter(Boolean).join(',');
  return '';
}

function externalProxyPins(value: any): string {
  if (Array.isArray(value)) return value.filter(Boolean).join(',');
  return '';
}

function applyExternalProxyTLSObj(
  externalProxy: any | null | undefined,
  obj: Record<string, unknown>,
  security: string
): void {
  if (!externalProxy || security !== 'tls') return;
  const sni =
    externalProxy.sni && externalProxy.sni.length > 0 ? externalProxy.sni : externalProxy.dest;
  if (sni && sni.length > 0) obj['sni'] = sni;
  if (externalProxy.fingerprint && externalProxy.fingerprint.length > 0)
    obj['fp'] = externalProxy.fingerprint;
  const alpn = externalProxyAlpn(externalProxy.alpn);
  if (alpn.length > 0) obj['alpn'] = alpn;
  const pins = externalProxyPins(externalProxy.pinnedPeerCertSha256);
  if (pins.length > 0) obj['pcs'] = pins;
  if (externalProxy.verifyPeerCertByName && externalProxy.verifyPeerCertByName.length > 0) {
    obj['vcn'] = externalProxy.verifyPeerCertByName;
  }
  if (externalProxy.echConfigList && externalProxy.echConfigList.length > 0)
    obj['ech'] = externalProxy.echConfigList;
}

export interface GenVmessLinkInput {
  inbound: any;
  address: string;
  port?: number;
  forceTls?: ForceTls;
  remark?: string;
  clientId: string;
  security?: string;
  externalProxy?: any | null;
}

/**
 * Generates a shareable VMess configuration link.
 *
 * @example
 * ```ts
 * const link = genVmessLink({
 *   inbound: myVmessInbound,
 *   address: '1.2.3.4',
 *   clientId: 'uuid-here',
 * });
 * ```
 */
export function genVmessLink(input: GenVmessLinkInput): string {
  const {
    inbound,
    address,
    port = inbound.port,
    forceTls = 'same',
    remark = '',
    clientId,
    security,
    externalProxy = null,
  } = input;

  if (inbound.protocol !== 'vmess') return '';

  const stream = inbound.streamSettings;
  if (!stream) return '';

  const tls = forceTls === 'same' ? (stream.security ?? 'none') : forceTls;
  const obj: Record<string, unknown> = {
    v: '2',
    ps: remark,
    add: address,
    port,
    id: clientId,
    scy: security,
    net: stream.network,
    tls,
  };

  if (stream.network === 'tcp') {
    const tcp = stream.tcpSettings;
    const header = tcp?.header;
    if (header) {
      obj['type'] = header.type;
      if (header.type === 'http') {
        const request = header.request;
        if (request) {
          obj['path'] = request.path.join(',');
          const host =
            getHeaderValue(header.response?.headers, 'host') ||
            getHeaderValue(request.headers, 'host');
          if (host) obj['host'] = host;
        }
      }
    } else {
      obj['type'] = 'none';
    }
  } else if (stream.network === 'kcp') {
    const kcp = stream.kcpSettings;
    if (kcp) {
      obj['mtu'] = kcp.mtu;
      obj['tti'] = kcp.tti;
    }
  } else if (stream.network === 'ws') {
    const ws = stream.wsSettings;
    if (ws) {
      obj['path'] = ws.path;
      obj['host'] = ws.host?.length > 0 ? ws.host : getHeaderValue(ws.headers, 'host');
    }
  } else if (stream.network === 'grpc') {
    const grpc = stream.grpcSettings;
    if (grpc) {
      obj['path'] = grpc.serviceName;
      obj['authority'] = grpc.authority;
      if (grpc.multiMode) obj['type'] = 'multi';
    }
  } else if (stream.network === 'httpupgrade') {
    const hu = stream.httpupgradeSettings;
    if (hu) {
      obj['path'] = hu.path;
      obj['host'] = hu.host?.length > 0 ? hu.host : getHeaderValue(hu.headers, 'host');
    }
  } else if (stream.network === 'xhttp') {
    const xhttp = stream.xhttpSettings;
    if (xhttp) {
      obj['path'] = xhttp.path;
      obj['host'] = xhttp.host?.length > 0 ? xhttp.host : xhttpHostFallback(xhttp);
      obj['type'] = xhttp.mode;
      applyXhttpExtraToObj(xhttp, obj);
    }
  }

  applyFinalMaskToObj(stream.finalmask, obj);

  if (tls === 'tls' && stream.security === 'tls') {
    const tlsSettings = stream.tlsSettings;
    if (tlsSettings) {
      if (tlsSettings.serverName?.length > 0) obj['sni'] = tlsSettings.serverName;
      if (tlsSettings.settings?.fingerprint?.length > 0)
        obj['fp'] = tlsSettings.settings.fingerprint;
      if (tlsSettings.alpn?.length > 0) obj['alpn'] = tlsSettings.alpn.join(',');
      if (tlsSettings.settings?.echConfigList?.length > 0)
        obj['ech'] = tlsSettings.settings.echConfigList;
      if (tlsSettings.settings?.verifyPeerCertByName?.length > 0) {
        obj['vcn'] = tlsSettings.settings.verifyPeerCertByName;
      }
      if (tlsSettings.settings?.pinnedPeerCertSha256?.length > 0) {
        obj['pcs'] = tlsSettings.settings.pinnedPeerCertSha256.join(',');
      }
    }
  }

  applyExternalProxyTLSObj(externalProxy, obj, tls);

  return 'vmess://' + Base64.encode(JSON.stringify(obj, null, 2));
}

function applyXhttpExtraToParams(xhttp: any | undefined, params: URLSearchParams): void {
  if (!xhttp) return;
  params.set('path', xhttp.path || '/');
  const host = xhttp.host?.length > 0 ? xhttp.host : xhttpHostFallback(xhttp);
  params.set('host', host);
  params.set('mode', xhttp.mode || 'auto');
  if (typeof xhttp.xPaddingBytes === 'string' && xhttp.xPaddingBytes.length > 0) {
    params.set('x_padding_bytes', xhttp.xPaddingBytes);
  }
  const extra = buildXhttpExtra(xhttp);
  if (extra) params.set('extra', JSON.stringify(extra));
}

function applyFinalMaskToParams(finalmask: any | undefined, params: URLSearchParams): void {
  const payload = serializeFinalMask(finalmask);
  if (payload.length > 0) params.set('fm', payload);
}

function applyExternalProxyTLSParams(
  externalProxy: any | null | undefined,
  params: URLSearchParams,
  security: string
): void {
  if (!externalProxy || security !== 'tls') return;
  const sni =
    externalProxy.sni && externalProxy.sni.length > 0 ? externalProxy.sni : externalProxy.dest;
  if (sni && sni.length > 0) params.set('sni', sni);
  if (externalProxy.fingerprint && externalProxy.fingerprint.length > 0)
    params.set('fp', externalProxy.fingerprint);
  const alpn = externalProxyAlpn(externalProxy.alpn);
  if (alpn.length > 0) params.set('alpn', alpn);
  const pins = externalProxyPins(externalProxy.pinnedPeerCertSha256);
  if (pins.length > 0) params.set('pcs', pins);
  if (externalProxy.verifyPeerCertByName && externalProxy.verifyPeerCertByName.length > 0) {
    params.set('vcn', externalProxy.verifyPeerCertByName);
  }
  if (externalProxy.echConfigList && externalProxy.echConfigList.length > 0)
    params.set('ech', externalProxy.echConfigList);
}

export interface GenVlessLinkInput {
  inbound: any;
  address: string;
  port?: number;
  forceTls?: ForceTls;
  remark?: string;
  clientId: string;
  flow?: string;
  externalProxy?: any | null;
}

/**
 * Generates a shareable VLESS configuration link.
 *
 * @example
 * ```ts
 * const link = genVlessLink({
 *   inbound: myVlessInbound,
 *   address: '1.2.3.4',
 *   clientId: 'uuid-here',
 * });
 * ```
 */
export function genVlessLink(input: GenVlessLinkInput): string {
  const {
    inbound,
    address,
    port = inbound.port,
    forceTls = 'same',
    remark = '',
    clientId,
    flow = '',
    externalProxy = null,
  } = input;

  if (inbound.protocol !== 'vless') return '';
  const stream = inbound.streamSettings;
  if (!stream) return '';

  const security = forceTls === 'same' ? stream.security : forceTls;
  const params = new URLSearchParams();
  params.set('type', stream.network ?? 'tcp');
  params.set('encryption', inbound.settings?.encryption || 'none');

  if (stream.network === 'tcp') {
    const tcp = stream.tcpSettings;
    if (tcp?.header?.type === 'http') {
      const request = tcp.header.request;
      if (request) {
        params.set('path', request.path.join(','));
        const host =
          getHeaderValue(tcp.header.response?.headers, 'host') ||
          getHeaderValue(request.headers, 'host');
        if (host) params.set('host', host);
        params.set('headerType', 'http');
      }
    }
  } else if (stream.network === 'kcp') {
    const kcp = stream.kcpSettings;
    if (kcp) {
      params.set('mtu', String(kcp.mtu));
      params.set('tti', String(kcp.tti));
    }
  } else if (stream.network === 'ws') {
    const ws = stream.wsSettings;
    if (ws) {
      params.set('path', ws.path);
      params.set('host', ws.host?.length > 0 ? ws.host : getHeaderValue(ws.headers, 'host'));
    }
  } else if (stream.network === 'grpc') {
    const grpc = stream.grpcSettings;
    if (grpc) {
      params.set('serviceName', grpc.serviceName);
      params.set('authority', grpc.authority);
      if (grpc.multiMode) params.set('mode', 'multi');
    }
  } else if (stream.network === 'httpupgrade') {
    const hu = stream.httpupgradeSettings;
    if (hu) {
      params.set('path', hu.path);
      params.set('host', hu.host?.length > 0 ? hu.host : getHeaderValue(hu.headers, 'host'));
    }
  } else if (stream.network === 'xhttp') {
    applyXhttpExtraToParams(stream.xhttpSettings, params);
  }

  applyFinalMaskToParams(stream.finalmask, params);

  if (security === 'tls') {
    params.set('security', 'tls');
    if (stream.security === 'tls') {
      const tls = stream.tlsSettings;
      if (tls) {
        params.set('fp', tls.settings?.fingerprint || '');
        params.set('alpn', tls.alpn?.join(',') || '');
        if (tls.serverName?.length > 0) params.set('sni', tls.serverName);
        if (tls.settings?.echConfigList?.length > 0) params.set('ech', tls.settings.echConfigList);
        if (tls.settings?.verifyPeerCertByName?.length > 0) {
          params.set('vcn', tls.settings.verifyPeerCertByName);
        }
        if (tls.settings?.pinnedPeerCertSha256?.length > 0) {
          params.set('pcs', tls.settings.pinnedPeerCertSha256.join(','));
        }
      }
    }
    applyExternalProxyTLSParams(externalProxy, params, security);
  } else if (security === 'reality') {
    params.set('security', 'reality');
    if (stream.security === 'reality') {
      const reality = stream.realitySettings;
      if (reality) {
        params.set('pbk', reality.settings?.publicKey || '');
        params.set('fp', reality.settings?.fingerprint || 'chrome');

        const sni =
          reality.settings?.serverName || reality.serverNames?.[0] || reality.target?.split(':')[0];

        if (sni && sni.length > 0) params.set('sni', sni);

        if (reality.shortIds?.length > 0) params.set('sid', reality.shortIds[0]);
        if (reality.settings?.spiderX?.length > 0) params.set('spx', reality.settings.spiderX);
        if (reality.settings?.mldsa65Verify?.length > 0)
          params.set('pqv', reality.settings.mldsa65Verify);
      }
    }
  } else {
    params.set('security', 'none');
  }

  if (
    flow.length > 0 &&
    canEnableTlsFlow({
      protocol: inbound.protocol,
      settings: inbound.settings,
      streamSettings: stream,
    })
  ) {
    params.set('flow', flow);
  }

  const url = new URL(`vless://${clientId}@${formatUrlHost(address)}:${port}`);
  for (const [key, value] of params) url.searchParams.set(key, value);
  url.hash = encodeURIComponent(remark);
  return url.toString();
}

function writeNetworkParams(stream: any, params: URLSearchParams): void {
  if (stream.network === 'tcp') {
    const tcp = stream.tcpSettings;
    if (tcp?.header?.type === 'http') {
      const request = tcp.header.request;
      if (request) {
        params.set('path', request.path.join(','));
        const host =
          getHeaderValue(tcp.header.response?.headers, 'host') ||
          getHeaderValue(request.headers, 'host');
        if (host) params.set('host', host);
        params.set('headerType', 'http');
      }
    }
  } else if (stream.network === 'kcp') {
    const kcp = stream.kcpSettings;
    if (kcp) {
      params.set('mtu', String(kcp.mtu));
      params.set('tti', String(kcp.tti));
    }
  } else if (stream.network === 'ws') {
    const ws = stream.wsSettings;
    if (ws) {
      params.set('path', ws.path);
      params.set('host', ws.host?.length > 0 ? ws.host : getHeaderValue(ws.headers, 'host'));
    }
  } else if (stream.network === 'grpc') {
    const grpc = stream.grpcSettings;
    if (grpc) {
      params.set('serviceName', grpc.serviceName);
      params.set('authority', grpc.authority);
      if (grpc.multiMode) params.set('mode', 'multi');
    }
  } else if (stream.network === 'httpupgrade') {
    const hu = stream.httpupgradeSettings;
    if (hu) {
      params.set('path', hu.path);
      params.set('host', hu.host?.length > 0 ? hu.host : getHeaderValue(hu.headers, 'host'));
    }
  } else if (stream.network === 'xhttp') {
    applyXhttpExtraToParams(stream.xhttpSettings, params);
  }
}

function writeTlsParams(stream: any, params: URLSearchParams): void {
  if (stream.security !== 'tls') return;
  const tls = stream.tlsSettings;
  if (tls) {
    params.set('fp', tls.settings?.fingerprint || '');
    params.set('alpn', tls.alpn?.join(',') || '');
    if (tls.settings?.echConfigList?.length > 0) params.set('ech', tls.settings.echConfigList);
    if (tls.serverName?.length > 0) params.set('sni', tls.serverName);
    if (tls.settings?.verifyPeerCertByName?.length > 0) {
      params.set('vcn', tls.settings.verifyPeerCertByName);
    }
    if (tls.settings?.pinnedPeerCertSha256?.length > 0) {
      params.set('pcs', tls.settings.pinnedPeerCertSha256.join(','));
    }
  }
}

function writeRealityParams(stream: any, params: URLSearchParams): void {
  if (stream.security !== 'reality') return;
  const reality = stream.realitySettings;
  if (reality) {
    params.set('pbk', reality.settings?.publicKey || '');
    params.set('fp', reality.settings?.fingerprint || 'chrome');

    const sni =
      reality.settings?.serverName || reality.serverNames?.[0] || reality.target?.split(':')[0];

    if (sni && sni.length > 0) params.set('sni', sni);

    if (reality.shortIds?.length > 0) params.set('sid', reality.shortIds[0]);
    if (reality.settings?.spiderX?.length > 0) params.set('spx', reality.settings.spiderX);
    if (reality.settings?.mldsa65Verify?.length > 0)
      params.set('pqv', reality.settings.mldsa65Verify);
  }
}

export interface GenTrojanLinkInput {
  inbound: any;
  address: string;
  port?: number;
  forceTls?: ForceTls;
  remark?: string;
  clientPassword: string;
  externalProxy?: any | null;
}

/**
 * Generates a shareable Trojan configuration link.
 */
export function genTrojanLink(input: GenTrojanLinkInput): string {
  const {
    inbound,
    address,
    port = inbound.port,
    forceTls = 'same',
    remark = '',
    clientPassword,
    externalProxy = null,
  } = input;

  if (inbound.protocol !== 'trojan') return '';
  const stream = inbound.streamSettings;
  if (!stream) return '';

  const security = forceTls === 'same' ? stream.security : forceTls;
  const params = new URLSearchParams();
  params.set('type', stream.network ?? 'tcp');

  writeNetworkParams(stream, params);
  applyFinalMaskToParams(stream.finalmask, params);

  if (security === 'tls') {
    params.set('security', 'tls');
    writeTlsParams(stream, params);
    applyExternalProxyTLSParams(externalProxy, params, security);
  } else if (security === 'reality') {
    params.set('security', 'reality');
    writeRealityParams(stream, params);
  } else {
    params.set('security', 'none');
  }

  const url = new URL(
    `trojan://${encodeURIComponent(clientPassword)}@${formatUrlHost(address)}:${port}`
  );
  for (const [key, value] of params) url.searchParams.set(key, value);
  url.hash = encodeURIComponent(remark);
  return url.toString();
}

export interface GenShadowsocksLinkInput {
  inbound: any;
  address: string;
  port?: number;
  forceTls?: ForceTls;
  remark?: string;
  clientPassword?: string;
  externalProxy?: any | null;
}

/**
 * Generates a shareable Shadowsocks configuration link.
 */
export function genShadowsocksLink(input: GenShadowsocksLinkInput): string {
  const {
    inbound,
    address,
    port = inbound.port,
    forceTls = 'same',
    remark = '',
    clientPassword = '',
    externalProxy = null,
  } = input;

  if (inbound.protocol !== 'shadowsocks') return '';
  const stream = inbound.streamSettings;
  if (!stream) return '';
  const settings = inbound.settings;

  const security = forceTls === 'same' ? stream.security : forceTls;
  const params = new URLSearchParams();
  params.set('type', stream.network ?? 'tcp');

  writeNetworkParams(stream, params);
  applyFinalMaskToParams(stream.finalmask, params);

  if (security === 'tls') {
    params.set('security', 'tls');
    writeTlsParams(stream, params);
    applyExternalProxyTLSParams(externalProxy, params, security);
  }

  if ((stream.network ?? 'tcp') === 'tcp' && params.get('headerType') === 'http') {
    const host = params.get('host') ?? '';
    params.delete('type');
    params.delete('headerType');
    params.delete('host');
    params.delete('path');
    params.set('plugin', `obfs-local;obfs=http;obfs-host=${host}`);
  }

  const isSS2022 = settings.method.substring(0, 4) === '2022';
  const isSSMultiUser = settings.method !== '2022-blake3-chacha20-poly1305';
  const passwords: string[] = [];
  if (isSS2022) passwords.push(settings.password);
  if (isSSMultiUser) passwords.push(clientPassword);

  if (isSS2022) {
    const userinfo = [settings.method, ...passwords].map(encodeURIComponent).join(':');
    let link = `ss://${userinfo}@${formatUrlHost(address)}:${port}`;
    const query = params.toString();
    if (query) link += `?${query}`;
    link += `#${encodeURIComponent(remark)}`;
    return link;
  }

  const userinfo = Base64.encode(`${settings.method}:${passwords.join(':')}`, { urlSafe: true });
  const url = new URL(`ss://${userinfo}@${formatUrlHost(address)}:${port}`);
  for (const [key, value] of params) url.searchParams.set(key, value);
  url.hash = encodeURIComponent(remark);
  return url.toString();
}

export interface GenHysteriaLinkInput {
  inbound: any;
  address: string;
  port?: number;
  remark?: string;
  clientAuth: string;
  externalProxy?: any | null;
}

function hysteriaPinHex(pin: string): string {
  const stripped = pin.trim().replace(/:/g, '');
  if (/^[0-9a-fA-F]{64}$/.test(stripped)) return stripped.toLowerCase();
  try {
    const binary = atob(pin.trim().replace(/-/g, '+').replace(/_/g, '/'));
    if (binary.length !== 32) return pin;
    let hex = '';
    for (let i = 0; i < binary.length; i++) {
      hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
  } catch {
    return pin;
  }
}

/**
 * Generates a shareable Hysteria configuration link.
 */
export function genHysteriaLink(input: GenHysteriaLinkInput): string {
  const {
    inbound,
    address,
    port = inbound.port,
    remark = '',
    clientAuth,
    externalProxy = null,
  } = input;

  if (inbound.protocol !== 'hysteria') return '';
  const stream = inbound.streamSettings;
  if (!stream || stream.security !== 'tls') return '';

  const settings = inbound.settings;
  const scheme = settings.version === 2 ? 'hysteria2' : 'hysteria';

  const params = new URLSearchParams();
  params.set('security', 'tls');
  const tls = stream.tlsSettings;
  if (tls) {
    if (tls.settings?.fingerprint?.length > 0) params.set('fp', tls.settings.fingerprint);
    if (tls.alpn?.length > 0) params.set('alpn', tls.alpn.join(','));
    if (tls.settings?.echConfigList?.length > 0) params.set('ech', tls.settings.echConfigList);
    if (tls.serverName?.length > 0) params.set('sni', tls.serverName);
    if (tls.settings?.verifyPeerCertByName?.length > 0) {
      params.set('vcn', tls.settings.verifyPeerCertByName);
    }
    if (tls.settings?.pinnedPeerCertSha256?.length > 0) {
      params.set('pinSHA256', tls.settings.pinnedPeerCertSha256.map(hysteriaPinHex).join(','));
    }
  }

  if (Array.isArray(externalProxy?.pinnedPeerCertSha256)) {
    const epPins = externalProxy.pinnedPeerCertSha256.filter(Boolean).map(hysteriaPinHex);
    if (epPins.length > 0) params.set('pinSHA256', epPins.join(','));
  }

  const udpMasks = stream.finalmask?.udp;
  if (Array.isArray(udpMasks)) {
    const salamander = udpMasks.find((m) => m?.type === 'salamander');
    const obfsPassword = salamander?.settings?.password;
    if (typeof obfsPassword === 'string' && obfsPassword.length > 0) {
      params.set('obfs', 'salamander');
      params.set('obfs-password', obfsPassword);
    }
  }

  applyFinalMaskToParams(stream.finalmask, params);

  const hopPorts = stream.finalmask?.quicParams?.udpHop?.ports?.trim() ?? '';
  if (hopPorts.length > 0) {
    params.set('mport', hopPorts);
  }

  const url = new URL(`${scheme}://${clientAuth}@${formatUrlHost(address)}:${port}`);
  for (const [key, value] of params) url.searchParams.set(key, value);
  url.hash = encodeURIComponent(remark);
  return url.toString();
}

export interface GenMtprotoLinkInput {
  inbound: any;
  address: string;
  port?: number;
}

/**
 * Generates a shareable MTProto proxy link.
 */
export function genMtprotoLink(input: GenMtprotoLinkInput): string {
  const { inbound, address, port = inbound.port } = input;
  if (inbound.protocol !== 'mtproto') return '';
  const secret = inbound.settings?.secret ?? '';
  if (secret.length === 0) return '';
  const url = new URL('tg://proxy');
  url.searchParams.set('server', address);
  url.searchParams.set('port', String(port));
  url.searchParams.set('secret', secret);
  return url.toString();
}

export interface GenWireguardLinkInput {
  settings: any;
  address: string;
  port: number;
  remark?: string;
  peerIndex: number;
}

/**
 * Generates a shareable Wireguard configuration link.
 */
export function genWireguardLink(input: GenWireguardLinkInput): string {
  const { settings, address, port, remark = '', peerIndex } = input;
  const peer = settings.peers[peerIndex];
  if (!peer) return '';

  const url = new URL(`wireguard://${formatUrlHost(address)}:${port}`);
  url.username = peer.privateKey ?? '';

  const pubKey =
    settings.secretKey?.length > 0 ? Wireguard.generateKeypair(settings.secretKey).publicKey : '';
  if (pubKey.length > 0) url.searchParams.set('publickey', pubKey);
  if (peer.allowedIPs?.length > 0 && peer.allowedIPs[0]) {
    url.searchParams.set('address', peer.allowedIPs[0]);
  }
  if (typeof settings.mtu === 'number' && settings.mtu > 0) {
    url.searchParams.set('mtu', String(settings.mtu));
  }

  url.hash = encodeURIComponent(remark);
  return url.toString();
}

/**
 * Generates a standard Wireguard configuration file content.
 */
export function genWireguardConfig(input: GenWireguardLinkInput): string {
  const { settings, address, port, remark = '', peerIndex } = input;
  const peer = settings.peers[peerIndex];
  if (!peer) return '';

  const pubKey =
    settings.secretKey?.length > 0 ? Wireguard.generateKeypair(settings.secretKey).publicKey : '';

  let txt = `[Interface]\n`;
  txt += `PrivateKey = ${peer.privateKey ?? ''}\n`;
  txt += `Address = ${peer.allowedIPs?.[0] ?? ''}\n`;
  txt += `DNS = ${settings.dns || '1.1.1.1, 1.0.0.1'}\n`;
  if (typeof settings.mtu === 'number' && settings.mtu > 0) {
    txt += `MTU = ${settings.mtu}\n`;
  }
  txt += `\n# ${remark}\n`;
  txt += `[Peer]\n`;
  txt += `PublicKey = ${pubKey}\n`;
  txt += `AllowedIPs = 0.0.0.0/0, ::/0\n`;
  txt += `Endpoint = ${address}:${port}`;
  if (peer.preSharedKey && peer.preSharedKey.length > 0) {
    txt += `\nPresharedKey = ${peer.preSharedKey}`;
  }
  if (typeof peer.keepAlive === 'number' && peer.keepAlive > 0) {
    txt += `\nPersistentKeepalive = ${peer.keepAlive}\n`;
  }
  return txt;
}

/**
 * Extracts client objects from inbound settings based on the protocol.
 */
export function getInboundClients(inbound: any): any[] | null {
  switch (inbound.protocol) {
    case 'vmess':
    case 'vless':
    case 'trojan':
    case 'hysteria':
      return (inbound.settings?.clients ?? []) as any[];
    case 'shadowsocks': {
      const isMultiUser = inbound.settings?.method !== '2022-blake3-chacha20-poly1305';
      return isMultiUser ? ((inbound.settings?.clients ?? []) as any[]) : null;
    }
    default:
      return null;
  }
}

export interface GenLinkInput {
  inbound: any;
  address: string;
  port?: number;
  forceTls?: ForceTls;
  remark?: string;
  client: any;
  externalProxy?: any | null;
}

/**
 * Generates a generic sharing link for various VPN protocols.
 */
export function genLink(input: GenLinkInput): string {
  const {
    inbound,
    address,
    port = inbound.port,
    forceTls = 'same',
    remark = '',
    client,
    externalProxy = null,
  } = input;
  switch (inbound.protocol) {
    case 'vmess':
      return genVmessLink({
        inbound,
        address,
        port,
        forceTls,
        remark,
        clientId: client.id ?? '',
        security: client.security,
        externalProxy,
      });
    case 'vless':
      return genVlessLink({
        inbound,
        address,
        port,
        forceTls,
        remark,
        clientId: client.id ?? '',
        flow: client.flow,
        externalProxy,
      });
    case 'shadowsocks': {
      const isMultiUser = inbound.settings?.method !== '2022-blake3-chacha20-poly1305';
      return genShadowsocksLink({
        inbound,
        address,
        port,
        forceTls,
        remark,
        clientPassword: isMultiUser ? (client.password ?? '') : '',
        externalProxy,
      });
    }
    case 'trojan':
      return genTrojanLink({
        inbound,
        address,
        port,
        forceTls,
        remark,
        clientPassword: client.password ?? '',
        externalProxy,
      });
    case 'hysteria':
      return genHysteriaLink({
        inbound,
        address,
        port,
        remark,
        clientAuth: client.auth ?? '',
        externalProxy,
      });
    case 'mtproto':
      return genMtprotoLink({ inbound, address, port });
    default:
      return '';
  }
}
