/**
 * Hybrid KEM: ML-KEM-1024 + X25519.
 *
 * Provides post-quantum security with a classical fallback:
 * - ML-KEM-1024 (NIST FIPS 203, Category 5) — secure unless a quantum computer
 *   capable of large-scale Shor/Grover exists AND the implementation is broken.
 * - X25519 — secure unless discrete log on Curve25519 is solved classically.
 * An attacker must break both simultaneously to recover the shared secret.
 *
 * Audit status:
 * - @noble/curves (X25519): audited by Cure53 ✅
 * - @noble/post-quantum (ML-KEM-1024): NOT yet independently audited ⚠️
 *   The hybrid design mitigates this — X25519 remains intact if ML-KEM-1024 has bugs.
 *
 * This module is internal. Application code uses channel.ts, which combines these
 * primitives with channel binding via HKDF-SHA512.
 */

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { ChannelKeypairs, _getKeypairInternal } from './types.js'
import type { ChannelPublicKey } from './types.js'

// ML-KEM-1024 key sizes (NIST FIPS 203, Section 2)
export const MLKEM_PUBLIC_KEY_BYTES = 1568
export const MLKEM_SECRET_KEY_BYTES = 3168
export const MLKEM_CIPHERTEXT_BYTES = 1568

// X25519 key / shared-secret size
export const DH_KEY_BYTES = 32

/**
 * Generate a hybrid ML-KEM-1024 + X25519 keypair.
 *
 * Both key types are generated with cryptographically random seeds.
 * Returns an opaque ChannelKeypairs handle — internal key bytes are not
 * accessible to application code. Use getPublicKey() to obtain the shareable
 * public portion and wrapKeyBundle() to persist the full keypair.
 */
export function generateChannelKeypairs(): ChannelKeypairs {
  const mlkem = ml_kem1024.keygen()

  const dhSecretKey = crypto.getRandomValues(new Uint8Array(DH_KEY_BYTES))
  const dhPublicKey = x25519.getPublicKey(dhSecretKey)

  return new ChannelKeypairs({
    mlkem: { publicKey: mlkem.publicKey, secretKey: mlkem.secretKey },
    dh: { publicKey: dhPublicKey, secretKey: dhSecretKey },
  })
}

/**
 * Extract the public portion of a keypair for sharing with recipients.
 *
 * The returned ChannelPublicKey is safe to share out-of-band (Signal, QR code, etc.).
 * It contains only public key material — no secret key bytes.
 */
export function getPublicKey(keypairs: ChannelKeypairs): ChannelPublicKey {
  const internal = _getKeypairInternal(keypairs)
  return {
    mlkem: internal.mlkem.publicKey,
    dh: internal.dh.publicKey,
  }
}

// ---------------------------------------------------------------------------
// Internal hybrid KEM operations — used exclusively by channel.ts
// ---------------------------------------------------------------------------

/**
 * @internal
 * Run hybrid KEM encapsulation against a recipient's public key.
 *
 * Returns the KEM ciphertext components and the raw shared secrets before
 * channel binding. channel.ts combines mlkemSs || dhSs with the channelId
 * via HKDF-SHA512 to derive the wrap key.
 */
export function hybridEncapsulate(recipient: ChannelPublicKey): {
  kemCt: Uint8Array
  dhEphemeral: Uint8Array
  mlkemSs: Uint8Array
  dhSs: Uint8Array
} {
  // ML-KEM-1024: encapsulate against recipient's public key
  const { cipherText: kemCt, sharedSecret: mlkemSs } = ml_kem1024.encapsulate(
    recipient.mlkem
  )

  // X25519: generate ephemeral keypair and compute DH shared secret
  const dhEphSk = crypto.getRandomValues(new Uint8Array(DH_KEY_BYTES))
  const dhEphPk = x25519.getPublicKey(dhEphSk)
  const dhSs = x25519.getSharedSecret(dhEphSk, recipient.dh)

  return { kemCt, dhEphemeral: dhEphPk, mlkemSs, dhSs }
}

/**
 * @internal
 * Recover shared secrets from KEM ciphertext using the recipient's secret key.
 *
 * channel.ts must combine mlkemSs || dhSs with the channelId via HKDF-SHA512
 * using the same parameters used during encapsulation. Do not use raw secrets
 * directly for any cryptographic operation.
 */
export function hybridDecapsulate(
  kemCt: Uint8Array,
  dhEphemeral: Uint8Array,
  keypairs: ChannelKeypairs
): { mlkemSs: Uint8Array; dhSs: Uint8Array } {
  const internal = _getKeypairInternal(keypairs)

  const mlkemSs = ml_kem1024.decapsulate(kemCt, internal.mlkem.secretKey)
  const dhSs = x25519.getSharedSecret(internal.dh.secretKey, dhEphemeral)

  return { mlkemSs, dhSs }
}
