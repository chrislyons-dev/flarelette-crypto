import { describe, it, expect } from 'vitest'
import {
  encapsulateChannelKey,
  decapsulateChannelKey,
  generateChannelKey,
} from '../src/channel.js'
import { generateChannelKeypairs, getPublicKey } from '../src/kem.js'

const CHANNEL_ID = 'channel-abc-123'

describe('encapsulateChannelKey / decapsulateChannelKey', () => {
  it('round-trip: recovers the original channel key', async () => {
    const keypairs = generateChannelKeypairs()
    const publicKey = getPublicKey(keypairs)
    const channelKey = generateChannelKey()

    const encapsulation = await encapsulateChannelKey(channelKey, publicKey, CHANNEL_ID)
    const recovered = await decapsulateChannelKey(encapsulation, keypairs, CHANNEL_ID)

    expect(recovered).toEqual(channelKey)
  })

  it('encapsulation carries the correct channelId', async () => {
    const keypairs = generateChannelKeypairs()
    const publicKey = getPublicKey(keypairs)
    const channelKey = generateChannelKey()

    const enc = await encapsulateChannelKey(channelKey, publicKey, CHANNEL_ID)
    expect(enc.channelId).toBe(CHANNEL_ID)
  })

  it('encapsulation carries recipientId when set on the public key', async () => {
    const keypairs = generateChannelKeypairs()
    const publicKey = getPublicKey(keypairs)
    publicKey.id = 'alice@example.com'
    const channelKey = generateChannelKey()

    const enc = await encapsulateChannelKey(channelKey, publicKey, CHANNEL_ID)
    expect(enc.recipientId).toBe('alice@example.com')
  })

  it('encapsulation fields have the expected sizes', async () => {
    const keypairs = generateChannelKeypairs()
    const publicKey = getPublicKey(keypairs)
    const channelKey = generateChannelKey()

    const enc = await encapsulateChannelKey(channelKey, publicKey, CHANNEL_ID)

    // ML-KEM-1024 ciphertext: 1568 bytes
    expect(enc.kemCt.length).toBe(1568)
    // X25519 ephemeral public key: 32 bytes
    expect(enc.dhEphemeral.length).toBe(32)
    // AES-GCM wraps 32-byte key → 32 + 16 (GCM tag) = 48 bytes
    expect(enc.wrappedKey.length).toBe(48)
    // 12-byte GCM IV
    expect(enc.wrapIv.length).toBe(12)
  })

  it('different encapsulations per call (ephemeral keys are random)', async () => {
    const keypairs = generateChannelKeypairs()
    const publicKey = getPublicKey(keypairs)
    const channelKey = generateChannelKey()

    const enc1 = await encapsulateChannelKey(channelKey, publicKey, CHANNEL_ID)
    const enc2 = await encapsulateChannelKey(channelKey, publicKey, CHANNEL_ID)

    // Each call generates fresh ephemeral X25519 and ML-KEM randomness
    expect(enc1.dhEphemeral).not.toEqual(enc2.dhEphemeral)
    expect(enc1.kemCt).not.toEqual(enc2.kemCt)
  })
})

describe('channel binding', () => {
  it('decapsulation with wrong channelId fails', async () => {
    const keypairs = generateChannelKeypairs()
    const publicKey = getPublicKey(keypairs)
    const channelKey = generateChannelKey()

    const enc = await encapsulateChannelKey(channelKey, publicKey, 'channel-A')

    await expect(decapsulateChannelKey(enc, keypairs, 'channel-B')).rejects.toThrow()
  })

  it('decapsulation with wrong keypair fails', async () => {
    const alice = generateChannelKeypairs()
    const bob = generateChannelKeypairs()
    const channelKey = generateChannelKey()

    // Encapsulate for Alice
    const enc = await encapsulateChannelKey(channelKey, getPublicKey(alice), CHANNEL_ID)

    // Bob cannot decapsulate Alice's encapsulation
    await expect(decapsulateChannelKey(enc, bob, CHANNEL_ID)).rejects.toThrow()
  })
})

describe('multi-recipient', () => {
  it('all recipients recover the same channel key', async () => {
    const alice = generateChannelKeypairs()
    const bob = generateChannelKeypairs()
    const carol = generateChannelKeypairs()

    const channelKey = generateChannelKey()

    const [encAlice, encBob, encCarol] = await Promise.all([
      encapsulateChannelKey(channelKey, getPublicKey(alice), CHANNEL_ID),
      encapsulateChannelKey(channelKey, getPublicKey(bob), CHANNEL_ID),
      encapsulateChannelKey(channelKey, getPublicKey(carol), CHANNEL_ID),
    ])

    const [keyAlice, keyBob, keyCarol] = await Promise.all([
      decapsulateChannelKey(encAlice, alice, CHANNEL_ID),
      decapsulateChannelKey(encBob, bob, CHANNEL_ID),
      decapsulateChannelKey(encCarol, carol, CHANNEL_ID),
    ])

    expect(keyAlice).toEqual(channelKey)
    expect(keyBob).toEqual(channelKey)
    expect(keyCarol).toEqual(channelKey)
  })

  it("recipient cannot use another recipient's encapsulation", async () => {
    const alice = generateChannelKeypairs()
    const bob = generateChannelKeypairs()
    const channelKey = generateChannelKey()

    const encAlice = await encapsulateChannelKey(
      channelKey,
      getPublicKey(alice),
      CHANNEL_ID
    )

    // Bob tries to use Alice's encapsulation
    await expect(decapsulateChannelKey(encAlice, bob, CHANNEL_ID)).rejects.toThrow()
  })
})

describe('input validation', () => {
  it('rejects channelKey shorter than 32 bytes', async () => {
    const kp = generateChannelKeypairs()
    const badKey = new Uint8Array(16)
    await expect(
      encapsulateChannelKey(badKey, getPublicKey(kp), CHANNEL_ID)
    ).rejects.toThrow('32 bytes')
  })

  it('rejects channelKey longer than 32 bytes', async () => {
    const kp = generateChannelKeypairs()
    const badKey = new Uint8Array(64)
    await expect(
      encapsulateChannelKey(badKey, getPublicKey(kp), CHANNEL_ID)
    ).rejects.toThrow('32 bytes')
  })
})
