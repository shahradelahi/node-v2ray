import { ChildProcessWithoutNullStreams, spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';

import { Commit, Version } from './constants';
import type { V2RayConfig } from './typings';

/**
 * A TypeScript-first Node.js wrapper for the V2Ray/Xray Go WebAssembly engine.
 * Provides an event-driven interface to run, start, stop, and configure V2Ray/Xray-core safely in a separate process.
 *
 * Emits:
 * - 'ready': When the engine/runner process is fully initialized and WebAssembly is loaded.
 * - 'log': Raw log lines output from the running V2Ray instance.
 * - 'started': When V2Ray successfully starts proxying with the provided configuration.
 * - 'stopped': When V2Ray successfully stops proxying.
 * - 'error': On initialization, process execution, or command-level errors.
 */
export class V2Ray extends EventEmitter {
  #process: ChildProcessWithoutNullStreams | null = null;
  #readyPromise: Promise<void>;
  #isReady = false;
  #isStarted = false;
  #startPromise: { resolve: () => void; reject: (err: Error) => void } | null = null;
  #stopPromise: { resolve: () => void; reject: (err: Error) => void } | null = null;

  constructor() {
    super();
    this.#readyPromise = this.#initialize();
  }

  async #initialize(): Promise<void> {
    const runnerPath = this.#getRunnerPath();
    const isTs = runnerPath.endsWith('.ts');

    if (isTs) {
      // Node.js 24 natively supports stripping types to execute TypeScript files directly
      this.#process = spawn(process.execPath, ['--experimental-strip-types', runnerPath]);
    } else {
      this.#process = spawn(process.execPath, [runnerPath]);
    }

    this.#process.stdout.on('data', (data: Buffer) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) {
          this.#handleOutput(trimmed);
        }
      }
    });

    this.#process.stderr.on('data', (data: Buffer) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) {
          this.#handleOutput(trimmed);
        }
      }
    });

    this.#process.on('error', (err) => {
      this.emit('error', err);
    });

    this.#process.on('exit', (code) => {
      this.#isReady = false;
      this.#isStarted = false;
      if (code !== 0 && code !== null) {
        const err = new Error(`V2Ray runner process exited with code ${code}`);
        if (this.#startPromise) {
          this.#startPromise.reject(err);
          this.#startPromise = null;
        }
        if (this.#stopPromise) {
          this.#stopPromise.reject(err);
          this.#stopPromise = null;
        }
        this.emit('error', err);
      }
    });

    await this.#waitEvent('ready');
    this.#isReady = true;
    this.emit('ready');
  }

  #getRunnerPath(): string {
    const runnerName = `v2ray-${Version}-${Commit}.cjs`;
    const paths = [path.join(__dirname, runnerName), path.join(__dirname, `../src/${runnerName}`)];

    for (const p of paths) {
      if (fs.existsSync(p)) {
        return p;
      }
    }

    throw new Error('V2Ray runner script not found. Make sure compilation is complete.');
  }

  #handleOutput(line: string): void {
    const prefix = '__v2ray_event__:';
    if (line.startsWith(prefix)) {
      try {
        const payload = JSON.parse(line.slice(prefix.length));
        this.#handleEvent(payload);
      } catch (err: any) {
        this.emit('error', new Error(`Failed to parse runner event payload: ${err.message}`));
      }
    } else {
      // Forward standard logs from V2Ray process to consumers
      this.emit('log', line);
    }
  }

  #handleEvent(payload: Record<string, any>): void {
    const event = payload['event'];
    this.emit(event, payload);

    if (event === 'started') {
      if (this.#startPromise) {
        this.#startPromise.resolve();
        this.#startPromise = null;
      }
      this.#isStarted = true;
    } else if (event === 'stopped') {
      if (this.#stopPromise) {
        this.#stopPromise.resolve();
        this.#stopPromise = null;
      }
      this.#isStarted = false;
    } else if (event === 'start_error') {
      if (this.#startPromise) {
        this.#startPromise.reject(new Error(payload['error'] || 'Failed to start V2Ray'));
        this.#startPromise = null;
      }
    } else if (event === 'stop_error') {
      if (this.#stopPromise) {
        this.#stopPromise.reject(new Error(payload['error'] || 'Failed to stop V2Ray'));
        this.#stopPromise = null;
      }
    } else if (event === 'error') {
      const err = new Error(payload['error'] || 'V2Ray runner error');
      this.emit('error', err);
    }
  }

  #waitEvent(eventName: string): Promise<any> {
    return new Promise((resolve) => {
      const listener = (payload: any) => {
        this.off(eventName, listener);
        resolve(payload);
      };
      this.on(eventName, listener);
    });
  }

  /**
   * Waits for the V2Ray runner process and WebAssembly to be fully initialized.
   * Essential before calling start().
   */
  async waitReady(): Promise<void> {
    if (this.#isReady) return;
    await this.#readyPromise;
  }

  /**
   * Starts the V2Ray service with the provided JSON configuration or string.
   * @param config The full V2Ray configuration.
   */
  async start(config: V2RayConfig | string): Promise<void> {
    await this.waitReady();
    if (this.#isStarted) {
      throw new Error('V2Ray is already running');
    }

    if (this.#startPromise) {
      throw new Error('Startup operation already in progress');
    }

    return new Promise<void>((resolve, reject) => {
      this.#startPromise = { resolve, reject };
      const configStr = typeof config === 'string' ? config : JSON.stringify(config);
      this.#send({ action: 'start', config: configStr });
    });
  }

  /**
   * Stops the currently running V2Ray service.
   */
  async stop(): Promise<void> {
    await this.waitReady();
    if (!this.#isStarted) {
      return;
    }

    if (this.#stopPromise) {
      throw new Error('Stop operation already in progress');
    }

    return new Promise<void>((resolve, reject) => {
      this.#stopPromise = { resolve, reject };
      this.#send({ action: 'stop' });
    });
  }

  #send(command: Record<string, any>): void {
    if (!this.#process?.stdin) {
      throw new Error('Runner process stdin is not available');
    }
    this.#process.stdin.write(JSON.stringify(command) + '\n');
  }

  /**
   * Safely shuts down the V2Ray runner child process.
   */
  terminate(): void {
    if (this.#process) {
      this.#process.kill();
      this.#process = null;
    }
    this.#isReady = false;
    this.#isStarted = false;
    this.#startPromise = null;
    this.#stopPromise = null;
  }

  /**
   * Returns whether the V2Ray runner is fully loaded and ready to accept commands.
   */
  get isReady(): boolean {
    return this.#isReady;
  }

  /**
   * Returns whether V2Ray is currently active and proxying.
   */
  get isStarted(): boolean {
    return this.#isStarted;
  }

  /**
   * Returns current library version metadata.
   */
  static get version(): string {
    return Version;
  }

  /**
   * Returns current build commit.
   */
  static get commit(): string {
    return Commit;
  }
}

// Export default and named configurations
export * from './typings';
export * from './xray/inbound-defaults';
export * from './xray/outbound-defaults';
export * from './xray/inbound-link';
export * from './xray/outbound-link-parser';
export * from './xray/protocol-capabilities';
export * from './xray/headers';
export * from './xray/stream-defaults';
export * from './xray/stream-wire-normalize';
export {
  RawInboundRow,
  WireInboundPayload,
  pruneEmpty,
  dropLegacyOptionalEmpties,
  normalizeSniffing,
  formValuesToWirePayload as inboundFormValuesToWirePayload,
} from './xray/inbound-form-adapter';

export {
  RawOutboundRow,
  rawOutboundToFormValues,
  formValuesToWirePayload as outboundFormValuesToWirePayload,
} from './xray/outbound-form-adapter';
