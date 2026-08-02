export interface V2RayConfig {
  log?: {
    access?: string;
    error?: string;
    loglevel?: 'debug' | 'info' | 'warning' | 'error' | 'none';
    dnsLog?: boolean;
  };
  api?: {
    tag?: string;
    services?: string[];
  };
  dns?: Record<string, any>;
  routing?: {
    domainStrategy?: 'AsIs' | 'IPIfNonMatch' | 'IPOnDemand';
    rules?: Record<string, any>[];
    balancers?: Record<string, any>[];
  };
  policy?: Record<string, any>;
  inbounds?: InboundConfig[];
  outbounds?: OutboundConfig[];
  transport?: Record<string, any>;
  stats?: Record<string, any>;
  reverse?: Record<string, any>;
  fakeDns?: Record<string, any>[];
  [key: string]: any;
}

export interface InboundConfig {
  port?: number | string;
  listen?: string;
  protocol: string;
  tag?: string;
  settings?: Record<string, any>;
  streamSettings?: StreamSettings;
  sniffing?: SniffingConfig;
}

export interface OutboundConfig {
  sendThrough?: string;
  protocol: string;
  settings?: Record<string, any>;
  tag?: string;
  streamSettings?: StreamSettings;
  proxySettings?: Record<string, any>;
  mux?: MuxConfig;
}

export interface SniffingConfig {
  enabled: boolean;
  destOverride?: string[];
  metadataOnly?: boolean;
  routeOnly?: boolean;
  ipsExcluded?: string[];
  domainsExcluded?: string[];
}

export interface MuxConfig {
  enabled: boolean;
  concurrency?: number;
  xudpConcurrency?: number;
  xudpProxyUDP443?: 'reject' | 'allow' | 'skip';
}

export interface StreamSettings {
  network?: 'tcp' | 'kcp' | 'ws' | 'grpc' | 'httpupgrade' | 'xhttp' | 'quic';
  security?: 'none' | 'tls' | 'reality';
  tlsSettings?: Record<string, any>;
  realitySettings?: Record<string, any>;
  tcpSettings?: Record<string, any>;
  kcpSettings?: Record<string, any>;
  wsSettings?: Record<string, any>;
  grpcSettings?: Record<string, any>;
  httpupgradeSettings?: Record<string, any>;
  xhttpSettings?: Record<string, any>;
  quicSettings?: Record<string, any>;
  sockopt?: Record<string, any>;
  finalmask?: Record<string, any>;
}
