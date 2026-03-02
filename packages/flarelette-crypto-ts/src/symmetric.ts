/**
 * Symmetric encryption primitives.
 *
 * AES-256-GCM via Web Crypto API (hardware-accelerated in browsers and Workers).
 * HMAC-SHA512 via @noble/hashes (audited by Cure53).
 *
 * All encryption uses Encrypt-then-MAC: AES-256-GCM first, then HMAC-SHA512 over
 * the ciphertext. Decryption verifies the MAC in constant time before attempting
 * to decrypt — fail-fast on tamper, no decryption oracle.
 */

import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { equalBytes } from '@noble/curves/utils.js'

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Convert a Uint8Array to a plain ArrayBuffer.
 *
 * Web Crypto requires ArrayBuffer (not ArrayBufferLike) for all key and data
 * parameters. Noble functions return Uint8Array<ArrayBufferLike>, which may
 * be backed by a SharedArrayBuffer. This ensures we always pass a plain
 * ArrayBuffer to satisfy both the DOM types and runtime requirements.
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  // ArrayBuffer.prototype.slice returns ArrayBuffer | SharedArrayBuffer in TypeScript's
  // DOM lib, but at runtime it always returns a plain ArrayBuffer. The cast is safe.
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

async function importAesKey(
  key: Uint8Array,
  usage: 'encrypt' | 'decrypt'
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toArrayBuffer(key), 'AES-GCM', false, [usage])
}

// ---------------------------------------------------------------------------
// AES-256-GCM (Web Crypto)
// ---------------------------------------------------------------------------

/**
 * AES-256-GCM encrypt.
 *
 * Returns ciphertext with the 16-byte GCM auth tag appended.
 * The caller is responsible for generating a unique 12-byte IV per encryption.
 * Reusing an IV with the same key is catastrophic — this function does not enforce
 * uniqueness; callers must generate IVs via randomIv().
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key, 'encrypt')
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    cryptoKey,
    toArrayBuffer(plaintext)
  )
  return new Uint8Array(ciphertext)
}

/**
 * AES-256-GCM decrypt.
 *
 * Throws if the GCM auth tag is invalid. This is a secondary authentication check;
 * callers should validate the outer HMAC-SHA512 MAC before calling this.
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key, 'decrypt')
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    cryptoKey,
    toArrayBuffer(ciphertext)
  )
  return new Uint8Array(plaintext)
}

// ---------------------------------------------------------------------------
// HMAC-SHA512 (@noble/hashes)
// ---------------------------------------------------------------------------

/**
 * Compute HMAC-SHA512.
 *
 * Used as the outer MAC in Encrypt-then-MAC. The message should include both
 * the nonce and the ciphertext to prevent nonce-swapping attacks.
 */
export function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha512, key, message)
}

/**
 * Constant-time byte equality check.
 *
 * Always use this — not ===, not a manual loop — when comparing MACs or secrets.
 * Timing-safe comparison prevents MAC oracle attacks.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a cryptographically random 12-byte IV for AES-GCM. */
export function randomIv(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(12))
}

/** Concatenate Uint8Arrays into a single Uint8Array. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    result.set(a, offset)
    offset += a.length
  }
  return result
}
