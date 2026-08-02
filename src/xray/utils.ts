import crypto from 'node:crypto';

/**
 * Utilities for WireGuard key generation.
 */
export class Wireguard {
  /**
   * Generates or derives a Curve25519 keypair for WireGuard.
   * @param privateKey Optional private key base64.
   * @example
   * ```ts
   * const keys = Wireguard.generateKeypair();
   * console.log(keys.privateKey, keys.publicKey);
   * ```
   */
  static generateKeypair(privateKey?: string) {
    if (privateKey) {
      try {
        const priv = crypto.createPrivateKey({
          key: Buffer.concat([
            Buffer.from([
              0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
              0x04, 0x20,
            ]),
            Buffer.from(privateKey, 'base64'),
          ]),
          format: 'der',
          type: 'pkcs8',
        });
        const pub = crypto.createPublicKey(priv);
        const pubDer = pub.export({ format: 'der', type: 'spki' });
        const publicKey = pubDer.subarray(16).toString('base64');
        return { privateKey, publicKey };
      } catch (e) {
        // Fallback to generating a keypair if parsing fails
      }
    }

    const { privateKey: privKey, publicKey: pubKey } = crypto.generateKeyPairSync('x25519');
    const generatedPrivateKey = privKey
      .export({ format: 'der', type: 'pkcs8' })
      .subarray(16)
      .toString('base64');
    const generatedPublicKey = pubKey
      .export({ format: 'der', type: 'spki' })
      .subarray(16)
      .toString('base64');
    return { privateKey: generatedPrivateKey, publicKey: generatedPublicKey };
  }
}
