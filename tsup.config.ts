import { promises } from 'node:fs';
import { join } from 'node:path';
import { defineConfig } from 'tsup';

import { Commit, Version } from './src/constants';

export default defineConfig([
  {
    clean: true,
    dts: true,
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    target: 'esnext',
    outDir: 'dist',
    shims: true,
    async onSuccess() {
      await promises.cp(
        join('src', `v2ray-${Version}-${Commit}.wasm.gz`),
        join('dist', `v2ray-${Version}-${Commit}.wasm.gz`)
      );
      await promises.cp(
        join('src', `v2ray-${Version}-${Commit}.cjs`),
        join('dist', `v2ray-${Version}-${Commit}.cjs`)
      );
    },
  },
]);
