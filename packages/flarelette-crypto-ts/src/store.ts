/**
 * Keypair persistence — wrap/unwrap and KeyStore implementations.
 *
 * Two concerns are separated intentionally:
 *
 * 1. `wrapKeyBundle` / `unwrapKeyBundle` — encrypt a keypair to a portable,
 *    JSON-serialisable WrappedBundle using Encrypt-then-MAC. Use this for
 *    export, backup, or when you need authenticated encryption at rest.
 *
 * 2. `KeyStore` / `open*Store` — an async key-value store for named keypairs.
 *    Stores raw serialized bytes (no encryption). Callers who need encryption
 *    should wrap/unwrap separately before storing.
 *
 * Bundle layout (serialized keypair — 4,800 bytes total):
 *
 *   mlkem_pk: 1568B @ offset    0
 *   mlkem_sk: 3168B @ offset 1568
 *   dh_pk:      32B @ offset 4736
 *   dh_sk:      32B @ offset 4768
 *
 * Encrypt-then-MAC protocol (same pattern as doc.ts):
 *   encKey = HKDF(wrappingKey, 'bundle-enc-v1') → 32B
 *   macKey = HKDF(wrappingKey, 'bundle-mac-v1') → 32B
 *   nonce  = random 12 bytes
 *   ciphertext = AES-256-GCM(encKey, nonce, serializedBytes)
 *   mac    = HMAC-SHA512(macKey, nonce || ciphertext)
 */

import type { WrappedBundle } from './types.js'
import { ChannelKeypairs, _getKeypairInternal } from './types.js'
import { MLKEM_PUBLIC_KEY_BYTES, MLKEM_SECRET_KEY_BYTES, DH_KEY_BYTES } from './kem.js'
import { deriveKey } from './derive.js'
import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  hmacSha512,
  constantTimeEqual,
  concatBytes,
  randomIv,
} from './symmetric.js'
import { base64urlEncode, base64urlDecode } from './codec.js'

// ---------------------------------------------------------------------------
// Internal serialization
// ---------------------------------------------------------------------------

const BUNDLE_BYTES =
  MLKEM_PUBLIC_KEY_BYTES + // 1568
  MLKEM_SECRET_KEY_BYTES + // 3168
  DH_KEY_BYTES + //   32
  DH_KEY_BYTES //   32
// = 4800

function serializeKeypairs(kp: ChannelKeypairs): Uint8Array {
  const internal = _getKeypairInternal(kp)
  const buf = new Uint8Array(BUNDLE_BYTES)
  let offset = 0
  buf.set(internal.mlkem.publicKey, offset)
  offset += MLKEM_PUBLIC_KEY_BYTES
  buf.set(internal.mlkem.secretKey, offset)
  offset += MLKEM_SECRET_KEY_BYTES
  buf.set(internal.dh.publicKey, offset)
  offset += DH_KEY_BYTES
  buf.set(internal.dh.secretKey, offset)
  return buf
}

function deserializeKeypairs(bytes: Uint8Array): ChannelKeypairs {
  if (bytes.length !== BUNDLE_BYTES) {
    throw new Error(
      `Invalid bundle: expected ${BUNDLE_BYTES} bytes, got ${bytes.length}`
    )
  }
  let offset = 0
  const mlkemPk = bytes.slice(offset, offset + MLKEM_PUBLIC_KEY_BYTES)
  offset += MLKEM_PUBLIC_KEY_BYTES
  const mlkemSk = bytes.slice(offset, offset + MLKEM_SECRET_KEY_BYTES)
  offset += MLKEM_SECRET_KEY_BYTES
  const dhPk = bytes.slice(offset, offset + DH_KEY_BYTES)
  offset += DH_KEY_BYTES
  const dhSk = bytes.slice(offset, offset + DH_KEY_BYTES)

  return new ChannelKeypairs({
    mlkem: { publicKey: mlkemPk, secretKey: mlkemSk },
    dh: { publicKey: dhPk, secretKey: dhSk },
  })
}

// ---------------------------------------------------------------------------
// wrapKeyBundle / unwrapKeyBundle
// ---------------------------------------------------------------------------

/**
 * Encrypt a keypair bundle with a wrapping key.
 *
 * The wrapping key is used as IKM for HKDF — it must be at least 32 bytes.
 * Typically derived from a user passphrase (Argon2id/scrypt) or from another
 * key exchange. Do not use a low-entropy string directly.
 *
 * Returns a JSON-serialisable object — all byte fields are base64url strings.
 */
export async function wrapKeyBundle(
  keypairs: ChannelKeypairs,
  wrappingKey: Uint8Array
): Promise<WrappedBundle> {
  if (wrappingKey.length < 32) {
    throw new Error(`wrappingKey must be at least 32 bytes, got ${wrappingKey.length}`)
  }

  const encKey = deriveKey(wrappingKey, 'bundle-enc-v1')
  const macKey = deriveKey(wrappingKey, 'bundle-mac-v1')

  const serialized = serializeKeypairs(keypairs)
  const nonce = randomIv()
  const ciphertext = await aesGcmEncrypt(encKey, nonce, serialized)
  const mac = hmacSha512(macKey, concatBytes(nonce, ciphertext))

  return {
    ciphertext: base64urlEncode(ciphertext),
    nonce: base64urlEncode(nonce),
    mac: base64urlEncode(mac),
  }
}

/**
 * Decrypt a keypair bundle produced by wrapKeyBundle().
 *
 * Verifies the HMAC-SHA512 MAC in constant time before attempting decryption.
 * Throws on MAC failure, wrong key, or any corrupt data — never returns a
 * partially recovered keypair.
 */
export async function unwrapKeyBundle(
  wrapped: WrappedBundle,
  wrappingKey: Uint8Array
): Promise<ChannelKeypairs> {
  if (wrappingKey.length < 32) {
    throw new Error(`wrappingKey must be at least 32 bytes, got ${wrappingKey.length}`)
  }

  const encKey = deriveKey(wrappingKey, 'bundle-enc-v1')
  const macKey = deriveKey(wrappingKey, 'bundle-mac-v1')

  const ciphertext = base64urlDecode(wrapped.ciphertext)
  const nonce = base64urlDecode(wrapped.nonce)
  const mac = base64urlDecode(wrapped.mac)

  const expectedMac = hmacSha512(macKey, concatBytes(nonce, ciphertext))
  if (!constantTimeEqual(expectedMac, mac)) {
    throw new Error('MAC verification failed: bundle may have been tampered with')
  }

  let plaintext: Uint8Array
  try {
    plaintext = await aesGcmDecrypt(encKey, nonce, ciphertext)
  } catch {
    throw new Error('Decryption failed: wrong wrapping key or corrupt bundle')
  }

  return deserializeKeypairs(plaintext)
}

// ---------------------------------------------------------------------------
// KeyStore interface
// ---------------------------------------------------------------------------

/**
 * Async key-value store for named keypairs.
 *
 * Stores raw serialized bytes — no encryption. Use wrapKeyBundle() / unwrapKeyBundle()
 * separately if you need authenticated encryption at rest.
 */
export interface KeyStore {
  save(name: string, keypairs: ChannelKeypairs): Promise<void>
  load(name: string): Promise<ChannelKeypairs | null>
  list(): Promise<string[]>
  delete(name: string): Promise<void>
}

// ---------------------------------------------------------------------------
// openMemoryStore
// ---------------------------------------------------------------------------

/**
 * In-memory KeyStore backed by a Map.
 *
 * Stores the opaque ChannelKeypairs handle directly — no serialization overhead.
 * Use in Node.js, Cloudflare Workers, and tests.
 * Data does not persist across process restarts.
 */
export function openMemoryStore(): KeyStore {
  const map = new Map<string, ChannelKeypairs>()

  return {
    async save(name, keypairs) {
      map.set(name, keypairs)
    },
    async load(name) {
      return map.get(name) ?? null
    },
    async list() {
      return [...map.keys()]
    },
    async delete(name) {
      map.delete(name)
    },
  }
}

// ---------------------------------------------------------------------------
// openIndexedDBStore
// ---------------------------------------------------------------------------

/**
 * IndexedDB-backed KeyStore.
 *
 * Serializes keypairs to 4,800-byte ArrayBuffers and stores them in an
 * IndexedDB object store. Data persists across page reloads.
 *
 * Uses lazy connection initialisation — the DB is opened on first use and
 * the connection is reused for subsequent operations.
 *
 * Object store name: 'keypairs'
 * DB version: 1
 */
export function openIndexedDBStore(dbName = 'flarelette-crypto'): KeyStore {
  const STORE_NAME = 'keypairs'

  let dbPromise: Promise<IDBDatabase> | null = null

  function getDb(): Promise<IDBDatabase> {
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName, 1)
        request.onupgradeneeded = event => {
          const db = (event.target as IDBOpenDBRequest).result
          if (!db.objectStoreNames.contains(STORE_NAME)) {
            db.createObjectStore(STORE_NAME)
          }
        }
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
      })
    }
    return dbPromise
  }

  function toBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength
    ) as ArrayBuffer
  }

  return {
    async save(name, keypairs) {
      const db = await getDb()
      const buf = toBuffer(serializeKeypairs(keypairs))
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite')
        const store = tx.objectStore(STORE_NAME)
        const request = store.put(buf, name)
        request.onsuccess = () => resolve()
        request.onerror = () => reject(request.error)
      })
    },

    async load(name) {
      const db = await getDb()
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly')
        const store = tx.objectStore(STORE_NAME)
        const request = store.get(name)
        request.onsuccess = () => {
          if (request.result === undefined) {
            resolve(null)
          } else {
            resolve(deserializeKeypairs(new Uint8Array(request.result as ArrayBuffer)))
          }
        }
        request.onerror = () => reject(request.error)
      })
    },

    async list() {
      const db = await getDb()
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly')
        const store = tx.objectStore(STORE_NAME)
        const request = store.getAllKeys()
        request.onsuccess = () => resolve(request.result as string[])
        request.onerror = () => reject(request.error)
      })
    },

    async delete(name) {
      const db = await getDb()
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite')
        const store = tx.objectStore(STORE_NAME)
        const request = store.delete(name)
        request.onsuccess = () => resolve()
        request.onerror = () => reject(request.error)
      })
    },
  }
}

// ---------------------------------------------------------------------------
// openKeyStore
// ---------------------------------------------------------------------------

/**
 * Open the best available KeyStore for the current environment.
 *
 * Returns an IndexedDB store if `indexedDB` is available (browsers), or
 * a memory store (Node.js, Cloudflare Workers).
 */
export function openKeyStore(options?: { dbName?: string }): KeyStore {
  return typeof indexedDB !== 'undefined'
    ? openIndexedDBStore(options?.dbName)
    : openMemoryStore()
}
