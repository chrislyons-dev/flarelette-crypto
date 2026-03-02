#!/usr/bin/env node
/**
 * flarelette-crypto-keygen — generate a hybrid ML-KEM-1024 + X25519 keypair.
 *
 * Usage:
 *   npx flarelette-crypto-keygen [--alg=hybrid] [--dotenv]
 *
 * Flags:
 *   --alg=hybrid   Key algorithm. Only 'hybrid' is supported.
 *   --dotenv       Output in .env format (default: JSON)
 *
 * Output (--dotenv):
 *   FLARELETTE_CRYPTO_KEYPAIR_SK=fcsk:hybrid:<base64url>
 *   FLARELETTE_CRYPTO_KEYPAIR_PK=fcpk:hybrid:<base64url>
 *
 * Deployment:
 *   Store SK as a Cloudflare secret — never commit it:
 *     wrangler secret put FLARELETTE_CRYPTO_KEYPAIR_SK
 *   PK can go in [vars] in wrangler.toml (it is public key material).
 */

import { generateChannelKeypairs } from '../kem.js'
import { keypairsToEnvVars } from '../adapters/workers.js'

// Minimal process interface — this file runs in Node.js only.
// We declare what we need rather than requiring @types/node globally.
interface NodeProcess {
  argv: string[]
  stdout: { write(s: string): boolean }
  stderr: { write(s: string): boolean }
  exit(code?: number): never
}
const proc = (globalThis as unknown as { process: NodeProcess }).process

function parseArgs(argv: string[]): { alg: string; dotenv: boolean } {
  const alg = argv.find(a => a.startsWith('--alg='))?.slice(6) ?? 'hybrid'
  const dotenv = argv.includes('--dotenv')
  return { alg, dotenv }
}

function main(): void {
  const { alg, dotenv } = parseArgs(proc.argv.slice(2))

  if (alg !== 'hybrid') {
    proc.stderr.write(`Unknown algorithm: ${alg}\nSupported algorithms: hybrid\n`)
    proc.exit(1)
  }

  const keypairs = generateChannelKeypairs()
  const { FLARELETTE_CRYPTO_KEYPAIR_SK, FLARELETTE_CRYPTO_KEYPAIR_PK } =
    keypairsToEnvVars(keypairs)

  if (dotenv) {
    proc.stdout.write(
      [
        '# flarelette-crypto keypair — ML-KEM-1024 + X25519',
        '# Store the secret key via: wrangler secret put FLARELETTE_CRYPTO_KEYPAIR_SK',
        '# The public key can go in [vars] in wrangler.toml',
        `FLARELETTE_CRYPTO_KEYPAIR_SK=${FLARELETTE_CRYPTO_KEYPAIR_SK}`,
        `FLARELETTE_CRYPTO_KEYPAIR_PK=${FLARELETTE_CRYPTO_KEYPAIR_PK}`,
        '',
      ].join('\n')
    )
  } else {
    proc.stdout.write(
      JSON.stringify(
        {
          sk: FLARELETTE_CRYPTO_KEYPAIR_SK,
          pk: FLARELETTE_CRYPTO_KEYPAIR_PK,
        },
        null,
        2
      ) + '\n'
    )
  }
}

main()
