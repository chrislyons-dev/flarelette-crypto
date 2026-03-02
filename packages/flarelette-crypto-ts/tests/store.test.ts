import { describe, it, expect } from 'vitest'
import 'fake-indexeddb/auto'
import {
  wrapKeyBundle,
  unwrapKeyBundle,
  openMemoryStore,
  openIndexedDBStore,
  openKeyStore,
} from '../src/store.js'
import { generateChannelKeypairs, getPublicKey } from '../src/kem.js'
import {
  generateChannelKey,
  encapsulateChannelKey,
  decapsulateChannelKey,
} from '../src/channel.js'
import { base64urlDecode, base64urlEncode } from '../src/codec.js'

// 32-byte wrapping key for tests
function makeWrappingKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

// Tamper a base64url field: decode, flip one byte, re-encode
function tamper(field: string): string {
  const bytes = base64urlDecode(field)
  const copy = new Uint8Array(bytes)
  copy[0] ^= 0xff
  return base64urlEncode(copy)
}

// ---------------------------------------------------------------------------
// wrapKeyBundle / unwrapKeyBundle
// ---------------------------------------------------------------------------

describe('wrapKeyBundle', () => {
  it('returns a WrappedBundle with 3 non-empty string fields', async () => {
    const kp = generateChannelKeypairs()
    const key = makeWrappingKey()
    const bundle = await wrapKeyBundle(kp, key)

    expect(typeof bundle.ciphertext).toBe('string')
    expect(typeof bundle.nonce).toBe('string')
    expect(typeof bundle.mac).toBe('string')
    expect(bundle.ciphertext.length).toBeGreaterThan(0)
    expect(bundle.nonce.length).toBeGreaterThan(0)
    expect(bundle.mac.length).toBeGreaterThan(0)
  })

  it('nonce decodes to 12 bytes', async () => {
    const bundle = await wrapKeyBundle(generateChannelKeypairs(), makeWrappingKey())
    expect(base64urlDecode(bundle.nonce).length).toBe(12)
  })

  it('mac decodes to 64 bytes (HMAC-SHA512)', async () => {
    const bundle = await wrapKeyBundle(generateChannelKeypairs(), makeWrappingKey())
    expect(base64urlDecode(bundle.mac).length).toBe(64)
  })

  it('throws when wrappingKey is shorter than 32 bytes', async () => {
    const kp = generateChannelKeypairs()
    await expect(wrapKeyBundle(kp, new Uint8Array(16))).rejects.toThrow('32 bytes')
  })
})

describe('wrap/unwrap round-trip', () => {
  it('recovered keypairs are functionally equivalent — can decapsulate a channel key', async () => {
    const original = generateChannelKeypairs()
    const wrappingKey = makeWrappingKey()
    const channelKey = generateChannelKey()
    const channelId = 'test-channel-round-trip'

    const bundle = await wrapKeyBundle(original, wrappingKey)
    const recovered = await unwrapKeyBundle(bundle, wrappingKey)

    // Prove functional equivalence: use recovered keypairs to decapsulate
    const enc = await encapsulateChannelKey(
      channelKey,
      getPublicKey(original),
      channelId
    )
    const decapped = await decapsulateChannelKey(enc, recovered, channelId)

    expect(decapped).toEqual(channelKey)
  })

  it('different wrapping keys produce different ciphertexts', async () => {
    const kp = generateChannelKeypairs()
    const key1 = makeWrappingKey()
    const key2 = makeWrappingKey()

    const b1 = await wrapKeyBundle(kp, key1)
    const b2 = await wrapKeyBundle(kp, key2)

    expect(b1.ciphertext).not.toBe(b2.ciphertext)
  })
})

describe('unwrapKeyBundle — tamper detection', () => {
  it('throws on wrong wrapping key (MAC error)', async () => {
    const kp = generateChannelKeypairs()
    const bundle = await wrapKeyBundle(kp, makeWrappingKey())
    await expect(unwrapKeyBundle(bundle, makeWrappingKey())).rejects.toThrow(
      'MAC verification'
    )
  })

  it('throws on MAC tamper', async () => {
    const kp = generateChannelKeypairs()
    const key = makeWrappingKey()
    const bundle = await wrapKeyBundle(kp, key)
    const tamperedBundle = { ...bundle, mac: tamper(bundle.mac) }
    await expect(unwrapKeyBundle(tamperedBundle, key)).rejects.toThrow(
      'MAC verification'
    )
  })

  it('throws on nonce tamper', async () => {
    const kp = generateChannelKeypairs()
    const key = makeWrappingKey()
    const bundle = await wrapKeyBundle(kp, key)
    const tampered = { ...bundle, nonce: tamper(bundle.nonce) }
    await expect(unwrapKeyBundle(tampered, key)).rejects.toThrow('MAC verification')
  })

  it('throws on ciphertext tamper', async () => {
    const kp = generateChannelKeypairs()
    const key = makeWrappingKey()
    const bundle = await wrapKeyBundle(kp, key)
    const tampered = { ...bundle, ciphertext: tamper(bundle.ciphertext) }
    await expect(unwrapKeyBundle(tampered, key)).rejects.toThrow('MAC verification')
  })

  it('throws when wrappingKey is shorter than 32 bytes on unwrap', async () => {
    const kp = generateChannelKeypairs()
    const key = makeWrappingKey()
    const bundle = await wrapKeyBundle(kp, key)
    await expect(unwrapKeyBundle(bundle, new Uint8Array(16))).rejects.toThrow(
      '32 bytes'
    )
  })
})

// ---------------------------------------------------------------------------
// openMemoryStore
// ---------------------------------------------------------------------------

describe('openMemoryStore', () => {
  it('save/load/list/delete round-trip', async () => {
    const store = openMemoryStore()
    const kp = generateChannelKeypairs()

    await store.save('alice', kp)
    const loaded = await store.load('alice')
    // Same handle in memory
    expect(loaded).toBe(kp)

    const names = await store.list()
    expect(names).toContain('alice')

    await store.delete('alice')
    const gone = await store.load('alice')
    expect(gone).toBeNull()
  })

  it('load unknown name returns null', async () => {
    const store = openMemoryStore()
    expect(await store.load('does-not-exist')).toBeNull()
  })

  it('delete then load returns null', async () => {
    const store = openMemoryStore()
    const kp = generateChannelKeypairs()
    await store.save('temp', kp)
    await store.delete('temp')
    expect(await store.load('temp')).toBeNull()
  })

  it('list returns all saved names', async () => {
    const store = openMemoryStore()
    await store.save('alice', generateChannelKeypairs())
    await store.save('bob', generateChannelKeypairs())
    const names = await store.list()
    expect(names.sort()).toEqual(['alice', 'bob'])
  })

  it('list returns empty array when store is empty', async () => {
    const store = openMemoryStore()
    expect(await store.list()).toEqual([])
  })

  it('overwrite: saving same name replaces the keypair', async () => {
    const store = openMemoryStore()
    const kp1 = generateChannelKeypairs()
    const kp2 = generateChannelKeypairs()
    await store.save('key', kp1)
    await store.save('key', kp2)
    expect(await store.load('key')).toBe(kp2)
  })
})

// ---------------------------------------------------------------------------
// openIndexedDBStore (via fake-indexeddb/auto)
// ---------------------------------------------------------------------------

let dbCounter = 0
function freshDbName(): string {
  return `test-db-${++dbCounter}`
}

describe('openIndexedDBStore (fake-indexeddb)', () => {
  it('save/load round-trip: recovered keypairs are functionally equivalent', async () => {
    const store = openIndexedDBStore(freshDbName())
    const original = generateChannelKeypairs()
    const channelId = 'idb-test-channel'
    const channelKey = generateChannelKey()

    await store.save('alice', original)
    const loaded = await store.load('alice')

    expect(loaded).not.toBeNull()

    // Prove functional equivalence via decapsulation
    const enc = await encapsulateChannelKey(
      channelKey,
      getPublicKey(original),
      channelId
    )
    const decapped = await decapsulateChannelKey(enc, loaded!, channelId)
    expect(decapped).toEqual(channelKey)
  })

  it('load unknown name returns null', async () => {
    const store = openIndexedDBStore(freshDbName())
    expect(await store.load('ghost')).toBeNull()
  })

  it('delete then load returns null', async () => {
    const store = openIndexedDBStore(freshDbName())
    await store.save('temp', generateChannelKeypairs())
    await store.delete('temp')
    expect(await store.load('temp')).toBeNull()
  })

  it('list returns all saved names', async () => {
    const store = openIndexedDBStore(freshDbName())
    await store.save('alice', generateChannelKeypairs())
    await store.save('bob', generateChannelKeypairs())
    const names = await store.list()
    expect(names.sort()).toEqual(['alice', 'bob'])
  })

  it('list returns empty array when store is empty', async () => {
    const store = openIndexedDBStore(freshDbName())
    expect(await store.list()).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// openKeyStore
// ---------------------------------------------------------------------------

describe('openKeyStore', () => {
  it('returns a working store (save/load round-trip)', async () => {
    // fake-indexeddb/auto sets global indexedDB, so openKeyStore returns IndexedDB store
    const store = openKeyStore({ dbName: freshDbName() })
    const kp = generateChannelKeypairs()

    await store.save('mykey', kp)
    const loaded = await store.load('mykey')
    expect(loaded).not.toBeNull()

    // Functional proof: same public key
    const pubOriginal = getPublicKey(kp)
    const pubLoaded = getPublicKey(loaded!)
    expect(pubLoaded.mlkem).toEqual(pubOriginal.mlkem)
    expect(pubLoaded.dh).toEqual(pubOriginal.dh)
  })
})
