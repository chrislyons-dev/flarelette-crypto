/**
 * Cloudflare Workers adapter — load keypairs from Worker env bindings.
 *
 * Use when IndexedDB is unavailable (Workers, edge runtimes). The keypair is
 * provided as two environment variables set at deploy time:
 *
 *   FLARELETTE_CRYPTO_KEYPAIR_SK — secret key bundle (fcsk:hybrid:...)
 *   FLARELETTE_CRYPTO_KEYPAIR_PK — public key bundle (fcpk:hybrid:...)
 *
 * Generate the values with:
 *   npx flarelette-crypto-keygen --alg=hybrid --dotenv
 *
 * Store the SK as a Cloudflare secret (never in wrangler.toml):
 *   wrangler secret put FLARELETTE_CRYPTO_KEYPAIR_SK
 *
 * The PK is public and can go in [vars].
 *
 * Supports _NAME indirection (mirrors flarelette-jwt-kit pattern):
 *   FLARELETTE_CRYPTO_KEYPAIR_SK_NAME=MY_SECRET → reads env.MY_SECRET
 *   FLARELETTE_CRYPTO_KEYPAIR_PK_NAME=MY_PUBLIC → reads env.MY_PUBLIC
 *
 * Secret key wire format:
 *   fcsk:hybrid:<base64url(mlkem_sk [3168B] || dh_sk [32B])>
 *   Payload: 3200 bytes → ~4267 base64url chars (within Cloudflare's 5 KB limit)
 *
 * Public key wire format:
 *   fcpk:hybrid:<base64url(mlkem_pk [1568B] || dh_pk [32B])>
 *   Same format as exportPublicBundle() — importPublicBundle() is used to decode it.
 */

import { ChannelKeypairs, _getKeypairInternal } from '../types.js'
import { exportPublicBundle, importPublicBundle } from '../serialize.js'
import { MLKEM_SECRET_KEY_BYTES, DH_KEY_BYTES } from '../kem.js'
import { base64urlEncode, base64urlDecode } from '../codec.js'

const SK_PREFIX = 'fcsk:hybrid:'
const SK_PAYLOAD_BYTES = MLKEM_SECRET_KEY_BYTES + DH_KEY_BYTES // 3200

function resolveEnvVar(
  env: Record<string, string>,
  varName: string
): string | undefined {
  const nameKey = `${varName}_NAME`
  const indirect = env[nameKey]
  return indirect !== undefined ? env[indirect] : env[varName]
}

/**
 * Serialize a keypair to env var strings for use in Worker bindings.
 *
 * Use this to generate the values that go in wrangler.toml [vars] and secrets.
 * The CLI (npx flarelette-crypto-keygen) uses this internally — you typically
 * don't need to call it directly unless you're managing keypairs programmatically.
 */
export function keypairsToEnvVars(keypairs: ChannelKeypairs): {
  FLARELETTE_CRYPTO_KEYPAIR_SK: string
  FLARELETTE_CRYPTO_KEYPAIR_PK: string
} {
  const internal = _getKeypairInternal(keypairs)

  const skBytes = new Uint8Array(SK_PAYLOAD_BYTES)
  skBytes.set(internal.mlkem.secretKey, 0)
  skBytes.set(internal.dh.secretKey, MLKEM_SECRET_KEY_BYTES)

  return {
    FLARELETTE_CRYPTO_KEYPAIR_SK: SK_PREFIX + base64urlEncode(skBytes),
    FLARELETTE_CRYPTO_KEYPAIR_PK: exportPublicBundle(keypairs),
  }
}

/**
 * Reconstruct a ChannelKeypairs from Worker env bindings.
 *
 * Reads FLARELETTE_CRYPTO_KEYPAIR_SK and FLARELETTE_CRYPTO_KEYPAIR_PK (or their
 * _NAME-indirected equivalents) and returns an opaque ChannelKeypairs handle.
 *
 * Call once per request (or cache the result). Throws immediately on any missing
 * or malformed binding — fail-fast prevents silent authentication with a bad key.
 *
 * @param env  The Worker env object, or any Record<string, string> for testing.
 */
export function keypairsFromEnv(env: Record<string, string>): ChannelKeypairs {
  const skRaw = resolveEnvVar(env, 'FLARELETTE_CRYPTO_KEYPAIR_SK')
  if (skRaw === undefined) {
    throw new Error(
      'FLARELETTE_CRYPTO_KEYPAIR_SK (or _NAME) is not set in the Worker environment'
    )
  }
  if (!skRaw.startsWith(SK_PREFIX)) {
    throw new Error(`FLARELETTE_CRYPTO_KEYPAIR_SK: expected prefix "${SK_PREFIX}"`)
  }

  const skBytes = base64urlDecode(skRaw.slice(SK_PREFIX.length))
  if (skBytes.length !== SK_PAYLOAD_BYTES) {
    throw new Error(
      `FLARELETTE_CRYPTO_KEYPAIR_SK: expected ${SK_PAYLOAD_BYTES} bytes, got ${skBytes.length}`
    )
  }

  const mlkemSk = skBytes.slice(0, MLKEM_SECRET_KEY_BYTES)
  const dhSk = skBytes.slice(MLKEM_SECRET_KEY_BYTES)

  const pkRaw = resolveEnvVar(env, 'FLARELETTE_CRYPTO_KEYPAIR_PK')
  if (pkRaw === undefined) {
    throw new Error(
      'FLARELETTE_CRYPTO_KEYPAIR_PK (or _NAME) is not set in the Worker environment'
    )
  }

  // importPublicBundle validates the prefix and byte length — throws on malformed input
  const publicKey = importPublicBundle(pkRaw)

  return new ChannelKeypairs({
    mlkem: { publicKey: publicKey.mlkem, secretKey: mlkemSk },
    dh: { publicKey: publicKey.dh, secretKey: dhSk },
  })
}
