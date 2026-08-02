import { describe, expect, it } from 'vitest';

import {
  canEnableReality,
  canEnableTls,
  createDefaultInboundSettings,
  createDefaultVlessClient,
  genVlessLink,
  parseOutboundLink,
  V2Ray,
} from './index';

describe('V2Ray Library Unit Tests', () => {
  it('should have version and commit static properties', () => {
    expect(V2Ray.version).toBeDefined();
    expect(V2Ray.commit).toBeDefined();
  });

  it('should support programmatically checking capabilities', () => {
    const inbound = {
      protocol: 'vless',
      streamSettings: {
        network: 'tcp',
        security: 'reality',
      },
    };
    expect(canEnableReality(inbound)).toBe(true);
    expect(canEnableTls(inbound)).toBe(true);
  });

  it('should generate default inbound configurations', () => {
    const vlessSettings = createDefaultInboundSettings('vless');
    expect(vlessSettings).toBeDefined();
    expect(vlessSettings.clients).toEqual([]);
    expect(vlessSettings.decryption).toBe('none');
  });

  it('should generate default clients', () => {
    const client = createDefaultVlessClient({ email: 'test@se-oss.com' });
    expect(client).toBeDefined();
    expect(client.email).toBe('test@se-oss.com');
    expect(client.id).toBeDefined();
  });

  it('should generate valid share links', () => {
    const inbound = {
      protocol: 'vless',
      port: 443,
      settings: {
        encryption: 'none',
      },
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: {
          settings: {
            publicKey: 'pubkey123',
            fingerprint: 'chrome',
          },
          target: 'google.com:443',
          shortIds: ['sid123'],
        },
      },
    };

    const link = genVlessLink({
      inbound,
      address: '1.2.3.4',
      clientId: 'uuid-123-456',
      flow: 'xtls-rprx-vision',
      remark: 'Test-Reality',
    });

    expect(link).toContain('vless://uuid-123-456@1.2.3.4:443');
    expect(link).toContain('security=reality');
    expect(link).toContain('pbk=pubkey123');
    expect(link).toContain('sid=sid123');
    expect(link).toContain('flow=xtls-rprx-vision');
  });

  it('should parse standard links correctly', () => {
    const link =
      'vless://uuid-123@1.2.3.4:443?type=tcp&security=reality&pbk=pubkey123&sid=sid123#Test-Remark';
    const parsed = parseOutboundLink(link);
    expect(parsed).toBeDefined();
    expect(parsed.protocol).toBe('vless');
    expect(parsed.tag).toBe('Test-Remark');
    expect(parsed.settings.address).toBe('1.2.3.4');
    expect(parsed.settings.port).toBe(443);
    expect(parsed.settings.id).toBe('uuid-123');
    expect(parsed.streamSettings.realitySettings.publicKey).toBe('pubkey123');
    expect(parsed.streamSettings.realitySettings.shortId).toBe('sid123');
  });
});

describe('V2Ray Runner Lifecycle Integration Tests', () => {
  it('should initialize the runner process and load WASM', async () => {
    const client = new V2Ray();

    // We expect the runner to load the WASM and transition to ready state successfully
    await client.waitReady();
    expect(client.isReady).toBe(true);
    expect(client.isStarted).toBe(false);

    client.terminate();
  });
});
