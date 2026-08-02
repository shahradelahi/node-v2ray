<h1 align="center">
  <sup>node-v2ray</sup>
  <br>
  <a href="https://github.com/shahradelahi/node-v2ray/actions/workflows/ci.yml"><img src="https://github.com/shahradelahi/node-v2ray/actions/workflows/ci.yml/badge.svg?branch=main&event=push" alt="CI"></a>
  <a href="https://www.npmjs.com/package/@se-oss/v2ray"><img src="https://img.shields.io/npm/v/@se-oss/v2ray.svg" alt="NPM Version"></a>
  <a href="/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat" alt="MIT License"></a>
  <a href="https://bundlephobia.com/package/@se-oss/v2ray"><img src="https://img.shields.io/bundlephobia/minzip/@se-oss/v2ray" alt="npm bundle size"></a>
  <a href="https://packagephobia.com/result?p=@se-oss/v2ray"><img src="https://packagephobia.com/badge?p=@se-oss/v2ray" alt="Install Size"></a>
</h1>

_@se-oss/v2ray_ is a TypeScript-first Node.js wrapper for the V2Ray/Xray Go WebAssembly engine. It provides an event-driven interface to run, start, stop, and configure V2Ray/Xray-core in a separate process, along with config scaffolding and link sharing utilities.

---

- [Installation](#-installation)
- [Usage](#-usage)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#license)

## 📦 Installation

```bash
npm install @se-oss/v2ray
```

<details>
<summary>Install using your favorite package manager</summary>

**pnpm**

```bash
pnpm install @se-oss/v2ray
```

**yarn**

```bash
yarn add @se-oss/v2ray
```

</details>

## 📖 Usage

### Basic Usage

Instantiate, initialize the WASM runtime, and start V2Ray with a configuration.

```ts
import { V2Ray } from '@se-oss/v2ray';

const client = new V2Ray();

// Wait for the WebAssembly loader to finish initialization
await client.waitReady();

client.on('log', (line) => {
  console.log('[V2Ray Log]:', line);
});

// Start proxying using standard V2Ray JSON configuration
await client.start({
  log: { loglevel: 'warning' },
  inbounds: [
    {
      port: 10808,
      listen: '127.0.0.1',
      protocol: 'socks',
      settings: { auth: 'noauth', udp: true },
    },
  ],
  outbounds: [
    {
      protocol: 'freedom',
      tag: 'direct',
    },
  ],
});

// Stop proxying
await client.stop();

// Safely shut down the runner child process
client.terminate();
```

### Config Scaffolding

Generate clean, valid inbounds and outbounds default configurations using helper factories.

```ts
import {
  createDefaultInboundSettings,
  createDefaultOutboundSettings,
} from '@se-oss/v2ray';

// Scaffold default VLESS Inbound settings
const vlessInbound = createDefaultInboundSettings('vless');
vlessInbound.clients.push({
  id: 'd9b042b3-769b-4e1b-bc9d-c7d9ec161c16',
  flow: 'xtls-rprx-vision',
  email: 'user@example.com',
});

// Scaffold default Shadowsocks Outbound settings
const ssOutbound = createDefaultOutboundSettings('shadowsocks');
```

### Link Generation

Generate universally compatible connection strings and sharing links.

```ts
import { genVlessLink } from '@se-oss/v2ray';

const inbound = {
  protocol: 'vless',
  port: 443,
  settings: { encryption: 'none' },
  streamSettings: {
    network: 'tcp',
    security: 'reality',
    realitySettings: {
      settings: { publicKey: 'pubkey123', fingerprint: 'chrome' },
      target: 'google.com:443',
      shortIds: ['sid123'],
    },
  },
};

const link = genVlessLink({
  inbound,
  address: 'my-server-ip.com',
  clientId: 'd9b042b3-769b-4e1b-bc9d-c7d9ec161c16',
  flow: 'xtls-rprx-vision',
  remark: 'Reality-VLESS-Connection',
});

console.log(link);
// Output: vless://d9b042b3-...@my-server-ip.com:443?type=tcp&security=reality&...#Reality-VLESS-Connection
```

### Link Parsing

Parse standard shareable links into valid V2Ray outbound records.

```ts
import { parseOutboundLink } from '@se-oss/v2ray';

const link =
  'vless://uuid-123@1.2.3.4:443?type=tcp&security=reality&pbk=pubkey123&sid=sid123#My-Server';
const parsed = parseOutboundLink(link);

console.log(parsed.protocol); // 'vless'
console.log(parsed.settings.address); // '1.2.3.4'
```

## 📚 Documentation

For all configuration options, please see [the API docs](https://www.jsdocs.io/package/@se-oss/v2ray).

## 🤝 Contributing

Want to contribute? Awesome! To show your support is to star the project, or to raise issues on [GitHub](https://github.com/shahradelahi/node-v2ray).

Thanks again for your support, it is much appreciated! 🙏

## License

[MIT](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi) and [contributors](https://github.com/shahradelahi/node-v2ray/graphs/contributors).
