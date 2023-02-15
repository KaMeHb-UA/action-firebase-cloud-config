import { defineConfig } from 'tsup';

export default defineConfig({
    target: 'node16',
    entry: ['src/index.ts'],
    noExternal: [/.*/],
    sourcemap: 'inline',
});
