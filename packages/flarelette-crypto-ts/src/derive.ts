/**
 * HKDF-SHA512 key derivation.
 *
 * All keys in flarelette-crypto are derived through this function.
 * Fixed salt prevents cross-context key reuse.
 */

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha512 } from '@noble/hashes/sha2.js'

const SALT = new TextEncoder().encode('flarelette-crypto-v1')

/**
 * Derive a key using HKDF-SHA512.
 *
 * @param ikm    Input key material (e.g. concatenated KEM shared secrets)
 * @param info   Context string — must be unique per key purpose and derivation site
 * @param length Output length in bytes (default: 32)
 */
export function deriveKey(ikm: Uint8Array, info: string, length = 32): Uint8Array {
  return hkdf(sha512, ikm, SALT, new TextEncoder().encode(info), length)
}
