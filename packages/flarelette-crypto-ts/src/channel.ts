/**
 * Channel key distribution — KEM layer.
 *
 * A "channel key" is a 32-byte symmetric key shared among channel members.
 * It is never serialised by this library — it lives in memory only.
 *
 * encapsulateChannelKey() wraps a channel key for one recipient using hybrid KEM:
 *   1. hybridEncapsulate() → ML-KEM-1024 ciphertext + X25519 ephemeral key + raw secrets
 *   2. HKDF-SHA512(mlkemSs || dhSs, info='channel-key-wrap:<channelId>') → 32-byte wrapKey
 *   3. AES-256-GCM(wrapKey, randomIv, channelKey) → wrappedKey
 *
 * The channelId is bound into the HKDF info parameter, so:
 * - A ChannelEncapsulation from channel A cannot be used to recover a key for channel B.
 * - Encapsulations are not transferable across channels, even with the same keypair.
 *
 * Call once per recipient. Pass the same channelKey for all recipients in the same channel.
 */

import type { ChannelEncapsulation, ChannelPublicKey } from './types.js'
import { ChannelKeypairs } from './types.js'

/**
 * Generate a random 32-byte channel key.
 *
 * Pass this to encapsulateChannelKey() for each channel member, then use it with
 * encryptDoc() to encrypt documents. Keep it in memory only — never serialise it.
 * To add a new member later, call encapsulateChannelKey() again with the same key.
 */
export function generateChannelKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}
import { hybridEncapsulate, hybridDecapsulate } from './kem.js'
import { deriveKey } from './derive.js'
import { aesGcmEncrypt, aesGcmDecrypt, concatBytes, randomIv } from './symmetric.js'

/** @internal HKDF info prefix for channel key wrapping. */
const WRAP_INFO_PREFIX = 'channel-key-wrap:'

/**
 * Wrap a channel key for one recipient using hybrid ML-KEM-1024 + X25519.
 *
 * Security properties:
 * - Channel binding: a returned ChannelEncapsulation is only valid for the given channelId.
 * - Recipient binding: only the holder of the matching ChannelKeypairs secret key can
 *   recover the channel key via decapsulateChannelKey().
 * - Forward secrecy (classical): ephemeral X25519 key is discarded after encapsulation.
 *
 * @param channelKey  32-byte random key shared among channel members. Generate with
 *                    generateChannelKey(). This value is never serialised by this library.
 * @param recipient   The recipient's public key, obtained from getPublicKey() or
 *                    importPublicBundle() (Phase 2).
 * @param channelId   Stable identifier for the channel (e.g. UUID or database row ID).
 *                    Must match exactly when calling decapsulateChannelKey().
 */
export async function encapsulateChannelKey(
  channelKey: Uint8Array,
  recipient: ChannelPublicKey,
  channelId: string
): Promise<ChannelEncapsulation> {
  if (channelKey.length !== 32) {
    throw new Error(`channelKey must be 32 bytes, got ${channelKey.length}`)
  }

  const { kemCt, dhEphemeral, mlkemSs, dhSs } = hybridEncapsulate(recipient)

  // Combine KEM shared secrets and derive a channel-bound wrap key via HKDF-SHA512
  const rawSecret = concatBytes(mlkemSs, dhSs) // 64 bytes: 32 (ML-KEM) + 32 (X25519)
  const wrapKey = deriveKey(rawSecret, `${WRAP_INFO_PREFIX}${channelId}`)

  const wrapIv = randomIv()
  const wrappedKey = await aesGcmEncrypt(wrapKey, wrapIv, channelKey)

  return {
    recipientId: recipient.id,
    channelId,
    kemCt,
    dhEphemeral,
    wrappedKey,
    wrapIv,
  }
}

/**
 * Recover a channel key from a ChannelEncapsulation using the recipient's secret key.
 *
 * Verifies channel binding — decapsulation fails if the channelId does not match
 * the one used during encapsulateChannelKey(). This is enforced cryptographically
 * via the HKDF info parameter: a mismatched channelId produces a different wrap key,
 * causing AES-GCM decryption to fail.
 *
 * @param encapsulation  Produced by encapsulateChannelKey() for this recipient.
 * @param keypairs       The recipient's full keypair (must include the secret key).
 * @param channelId      Must match the channelId used during encapsulation.
 * @returns              The 32-byte channel key.
 * @throws               If the channelId is wrong, the encapsulation is corrupt, or
 *                       the keypair does not match.
 */
export async function decapsulateChannelKey(
  encapsulation: ChannelEncapsulation,
  keypairs: ChannelKeypairs,
  channelId: string
): Promise<Uint8Array> {
  const { mlkemSs, dhSs } = hybridDecapsulate(
    encapsulation.kemCt,
    encapsulation.dhEphemeral,
    keypairs
  )

  // Derive wrap key with the same channelId — mismatch produces wrong key → GCM failure
  const rawSecret = concatBytes(mlkemSs, dhSs)
  const wrapKey = deriveKey(rawSecret, `${WRAP_INFO_PREFIX}${channelId}`)

  // AES-GCM decryption; throws DOMException if GCM auth tag fails
  try {
    return await aesGcmDecrypt(wrapKey, encapsulation.wrapIv, encapsulation.wrappedKey)
  } catch {
    throw new Error(
      'Channel key decapsulation failed: wrong keypair, wrong channelId, or corrupt encapsulation'
    )
  }
}
