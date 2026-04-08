import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: [
      {
        find: '@chrislyons-dev/flarelette-crypto/adapters/workers',
        replacement: '/packages/flarelette-crypto-ts/src/adapters/workers.ts',
      },
      {
        find: '@chrislyons-dev/flarelette-crypto',
        replacement: '/packages/flarelette-crypto-ts/src/index.ts',
      },
    ],
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['packages/**/tests/**/*.test.ts', 'packages/**/tests/**/*.spec.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'html', 'lcov', 'json'],
      include: ['packages/*/src/**/*.ts'],
      exclude: [
        '**/node_modules/**',
        '**/dist/**',
        '**/tests/**',
        '**/*.test.ts',
        '**/*.spec.ts',
        '**/types.ts',
        '**/index.ts',
      ],
    },
  },
})
