import { describe, it, expect } from 'vitest'
import { encryptDoc, decryptDoc } from '../src/doc.js'
import { generateChannelKey } from '../src/channel.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function text(s: string): Uint8Array {
  return encoder.encode(s)
}

describe('encryptDoc / decryptDoc', () => {
  it('round-trip: recovers the original plaintext', async () => {
    const masterKey = generateChannelKey()
    const plaintext = text('Hello, flarelette-crypto!')

    const doc = await encryptDoc(plaintext, masterKey)
    const recovered = await decryptDoc(doc, masterKey)

    expect(decoder.decode(recovered)).toBe('Hello, flarelette-crypto!')
  })

  it('round-trip with empty plaintext', async () => {
    const masterKey = generateChannelKey()
    const doc = await encryptDoc(new Uint8Array(0), masterKey)
    const recovered = await decryptDoc(doc, masterKey)
    expect(recovered.length).toBe(0)
  })

  it('round-trip with large plaintext (1 MB)', async () => {
    const masterKey = generateChannelKey()
    // crypto.getRandomValues is limited to 65,536 bytes per call; fill in chunks
    const plaintext = new Uint8Array(1024 * 1024)
    for (let i = 0; i < plaintext.length; i += 65536) {
      crypto.getRandomValues(plaintext.subarray(i, i + 65536))
    }

    const doc = await encryptDoc(plaintext, masterKey)
    const recovered = await decryptDoc(doc, masterKey)

    expect(recovered).toEqual(plaintext)
  }, 15000)

  it('produces different ciphertext each call (random nonce)', async () => {
    const masterKey = generateChannelKey()
    const plaintext = text('determinism check')

    const doc1 = await encryptDoc(plaintext, masterKey)
    const doc2 = await encryptDoc(plaintext, masterKey)

    expect(doc1.nonce).not.toEqual(doc2.nonce)
    expect(doc1.ciphertext).not.toEqual(doc2.ciphertext)
  })

  it('nonce is 12 bytes', async () => {
    const doc = await encryptDoc(text('x'), generateChannelKey())
    expect(doc.nonce.length).toBe(12)
  })

  it('mac is 64 bytes (HMAC-SHA512)', async () => {
    const doc = await encryptDoc(text('x'), generateChannelKey())
    expect(doc.mac.length).toBe(64)
  })

  it('ciphertext is plaintext length + 16 bytes (AES-GCM tag)', async () => {
    const masterKey = generateChannelKey()
    const plaintext = text('twelve bytes')
    const doc = await encryptDoc(plaintext, masterKey)
    // AES-256-GCM appends a 16-byte authentication tag
    expect(doc.ciphertext.length).toBe(plaintext.length + 16)
  })
})

describe('MAC verification', () => {
  it('throws when mac is tampered with', async () => {
    const masterKey = generateChannelKey()
    const doc = await encryptDoc(text('secret'), masterKey)

    // Flip a byte in the MAC
    const tamperedMac = new Uint8Array(doc.mac)
    tamperedMac[0] ^= 0xff
    const tamperedDoc = { ...doc, mac: tamperedMac }

    await expect(decryptDoc(tamperedDoc, masterKey)).rejects.toThrow(
      'MAC verification failed'
    )
  })

  it('throws when ciphertext is tampered with', async () => {
    const masterKey = generateChannelKey()
    const doc = await encryptDoc(text('secret'), masterKey)

    const tamperedCt = new Uint8Array(doc.ciphertext)
    tamperedCt[0] ^= 0xff
    const tamperedDoc = { ...doc, ciphertext: tamperedCt }

    // MAC is over the original ciphertext, so tampered ciphertext → MAC failure
    await expect(decryptDoc(tamperedDoc, masterKey)).rejects.toThrow(
      'MAC verification failed'
    )
  })

  it('throws when nonce is tampered with', async () => {
    const masterKey = generateChannelKey()
    const doc = await encryptDoc(text('secret'), masterKey)

    // Nonce is part of the MAC input (nonce || ciphertext), so tampering it breaks the MAC
    const tamperedNonce = new Uint8Array(doc.nonce)
    tamperedNonce[0] ^= 0xff
    const tamperedDoc = { ...doc, nonce: tamperedNonce }

    await expect(decryptDoc(tamperedDoc, masterKey)).rejects.toThrow(
      'MAC verification failed'
    )
  })

  it('does not attempt decryption when MAC fails', async () => {
    // Ensure the error message is specifically about MAC, not about GCM decryption
    const masterKey = generateChannelKey()
    const doc = await encryptDoc(text('secret'), masterKey)

    const tamperedMac = new Uint8Array(doc.mac)
    tamperedMac[0] ^= 0xff

    try {
      await decryptDoc({ ...doc, mac: tamperedMac }, masterKey)
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as Error).message).toContain('MAC verification failed')
    }
  })
})

describe('cross-channel isolation', () => {
  it('doc encrypted with key A cannot be decrypted with key B', async () => {
    const keyA = generateChannelKey()
    const keyB = generateChannelKey()

    const doc = await encryptDoc(text('channel A secret'), keyA)

    // Either throws on MAC (likely) or produces garbage (should not happen with Encrypt-then-MAC)
    await expect(decryptDoc(doc, keyB)).rejects.toThrow()
  })
})

describe('input validation', () => {
  it('rejects masterKey shorter than 32 bytes on encrypt', async () => {
    await expect(encryptDoc(text('x'), new Uint8Array(16))).rejects.toThrow('32 bytes')
  })

  it('rejects masterKey shorter than 32 bytes on decrypt', async () => {
    const doc = await encryptDoc(text('x'), generateChannelKey())
    await expect(decryptDoc(doc, new Uint8Array(16))).rejects.toThrow('32 bytes')
  })
})
