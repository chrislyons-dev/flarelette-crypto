/**
 * Document encryption — symmetric layer.
 *
 * Encrypts arbitrary plaintext (document content, metadata, message body) using
 * a 32-byte channel key obtained from decapsulateChannelKey().
 *
 * Protocol: Encrypt-then-MAC
 *   1. Derive encKey = HKDF-SHA512(masterKey, 'doc-enc-v1') → 32 bytes
 *   2. Derive macKey = HKDF-SHA512(masterKey, 'doc-mac-v1') → 32 bytes
 *   3. nonce = random 12 bytes
 *   4. ciphertext = AES-256-GCM(encKey, nonce, plaintext)  [includes 16-byte GCM tag]
 *   5. mac = HMAC-SHA512(macKey, nonce || ciphertext)
 *   6. Return { ciphertext, nonce, mac }
 *
 * Decryption verifies the HMAC before attempting AES-GCM decryption. Fail-fast
 * on tamper: the MAC check prevents a decryption oracle from exposing GCM internals.
 * Key separation (distinct encKey and macKey) follows cryptographic best practice.
 */

import type { EncryptedDoc } from './types.js'
import { deriveKey } from './derive.js'
import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  hmacSha512,
  constantTimeEqual,
  concatBytes,
  randomIv,
} from './symmetric.js'

/**
 * Encrypt plaintext with a channel key.
 *
 * The channel key (masterKey) is never serialised by this function — it is the
 * caller's responsibility to keep it in memory only and distribute it via
 * encapsulateChannelKey(). Any byte sequence (document, metadata blob, message body)
 * can be encrypted as a single call; encrypt metadata and content together in a
 * single plaintext rather than separately.
 *
 * @param plaintext  Arbitrary bytes to encrypt.
 * @param masterKey  32-byte channel key from decapsulateChannelKey().
 */
export async function encryptDoc(
  plaintext: Uint8Array,
  masterKey: Uint8Array
): Promise<EncryptedDoc> {
  if (masterKey.length !== 32) {
    throw new Error(`masterKey must be 32 bytes, got ${masterKey.length}`)
  }

  const encKey = deriveKey(masterKey, 'doc-enc-v1')
  const macKey = deriveKey(masterKey, 'doc-mac-v1')

  const nonce = randomIv()
  const ciphertext = await aesGcmEncrypt(encKey, nonce, plaintext)

  // MAC over nonce || ciphertext — prevents nonce-swapping attacks
  const mac = hmacSha512(macKey, concatBytes(nonce, ciphertext))

  return { ciphertext, nonce, mac }
}

/**
 * Decrypt a document encrypted by encryptDoc().
 *
 * Verifies the HMAC-SHA512 MAC in constant time before attempting decryption.
 * Throws immediately on MAC failure — no partial decryption, no timing oracle.
 *
 * @param doc        Produced by encryptDoc().
 * @param masterKey  The same 32-byte channel key used for encryption.
 * @throws           If the MAC is invalid or decryption fails (wrong key, corrupt data).
 */
export async function decryptDoc(
  doc: EncryptedDoc,
  masterKey: Uint8Array
): Promise<Uint8Array> {
  if (masterKey.length !== 32) {
    throw new Error(`masterKey must be 32 bytes, got ${masterKey.length}`)
  }

  const encKey = deriveKey(masterKey, 'doc-enc-v1')
  const macKey = deriveKey(masterKey, 'doc-mac-v1')

  // Verify MAC before any decryption attempt
  const expectedMac = hmacSha512(macKey, concatBytes(doc.nonce, doc.ciphertext))
  if (!constantTimeEqual(expectedMac, doc.mac)) {
    throw new Error('MAC verification failed: ciphertext may have been tampered with')
  }

  try {
    return await aesGcmDecrypt(encKey, doc.nonce, doc.ciphertext)
  } catch {
    throw new Error('Decryption failed: wrong key or corrupt ciphertext')
  }
}
