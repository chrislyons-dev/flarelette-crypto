/**
 * Public key serialization for out-of-band sharing.
 *
 * Wire format: `fcpk:hybrid:<base64url(mlkem_pk [1568B] || dh_pk [32B])>`
 * Total payload: 1600 bytes → ~2134 base64url characters.
 *
 * The "hybrid" prefix is algorithm-stable — it identifies the key type, not the
 * specific curve choices. If key sizes stay the same, the prefix remains valid
 * across minor algorithm updates. A size change requires a new prefix.
 *
 * Usage:
 *   // Alice exports her public key for sharing (Signal, QR code, etc.)
 *   const bundle = exportPublicBundle(aliceKeypairs)
 *
 *   // Bob imports it to encapsulate a channel key for Alice
 *   const alicePublicKey = importPublicBundle(bundle)
 *   const enc = await encapsulateChannelKey(channelKey, alicePublicKey, channelId)
 */

import type { ChannelPublicKey } from './types.js'
import type { ChannelKeypairs } from './types.js'
import { getPublicKey } from './kem.js'
import { MLKEM_PUBLIC_KEY_BYTES, DH_KEY_BYTES } from './kem.js'
import { base64urlEncode, base64urlDecode } from './codec.js'

const PREFIX = 'fcpk:hybrid:'
const TOTAL_BYTES = MLKEM_PUBLIC_KEY_BYTES + DH_KEY_BYTES // 1568 + 32 = 1600

/**
 * Serialize the public portion of a keypair to a compact, shareable string.
 *
 * The returned string is safe to share over any channel (Signal, QR code,
 * paste into a form). It contains only public key material.
 */
export function exportPublicBundle(keypairs: ChannelKeypairs): string {
  const pub = getPublicKey(keypairs)
  const combined = new Uint8Array(TOTAL_BYTES)
  combined.set(pub.mlkem, 0)
  combined.set(pub.dh, MLKEM_PUBLIC_KEY_BYTES)
  return PREFIX + base64urlEncode(combined)
}

/**
 * Deserialize a public bundle string to a ChannelPublicKey.
 *
 * Validates the prefix and byte length. Throws on any malformed input —
 * never returns a partial or zero-initialized key.
 */
export function importPublicBundle(encoded: string): ChannelPublicKey {
  if (!encoded.startsWith(PREFIX)) {
    throw new Error(
      `Invalid public bundle: expected prefix "${PREFIX}", got "${encoded.slice(0, PREFIX.length + 4)}..."`
    )
  }

  const payload = encoded.slice(PREFIX.length)
  const bytes = base64urlDecode(payload)

  if (bytes.length !== TOTAL_BYTES) {
    throw new Error(
      `Invalid public bundle: expected ${TOTAL_BYTES} bytes, got ${bytes.length}`
    )
  }

  return {
    mlkem: bytes.slice(0, MLKEM_PUBLIC_KEY_BYTES),
    dh: bytes.slice(MLKEM_PUBLIC_KEY_BYTES),
  }
}
