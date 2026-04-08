import { describe, expect, it } from 'vitest'
import 'fake-indexeddb/auto'
import {
  decapsulateChannelKey,
  decryptDoc,
  encryptDoc,
  exportPublicBundle,
  generateChannelKey,
  generateChannelKeypairs,
  getPublicKey,
  importPublicBundle,
  openKeyStore,
  wrapKeyBundle,
  unwrapKeyBundle,
  encapsulateChannelKey,
} from '@chrislyons-dev/flarelette-crypto'

describe('public root API', () => {
  it('supports the documented channel encryption flow through the package entrypoint', async () => {
    const aliceKeypairs = generateChannelKeypairs()
    const alicePublicKey = getPublicKey(aliceKeypairs)
    const importedPublicKey = importPublicBundle(exportPublicBundle(aliceKeypairs))

    expect(importedPublicKey.mlkem).toEqual(alicePublicKey.mlkem)
    expect(importedPublicKey.dh).toEqual(alicePublicKey.dh)

    const channelKey = generateChannelKey()
    const channelId = 'public-api-channel'
    const encapsulation = await encapsulateChannelKey(
      channelKey,
      importedPublicKey,
      channelId
    )
    const recoveredKey = await decapsulateChannelKey(
      encapsulation,
      aliceKeypairs,
      channelId
    )

    expect(recoveredKey).toEqual(channelKey)

    const plaintext = new TextEncoder().encode('public api round-trip')
    const encrypted = await encryptDoc(plaintext, recoveredKey)
    const decrypted = await decryptDoc(encrypted, recoveredKey)

    expect(new TextDecoder().decode(decrypted)).toBe('public api round-trip')
  })

  it('supports public wrap and store flows without importing internals', async () => {
    const keypairs = generateChannelKeypairs()
    const wrappingKey = crypto.getRandomValues(new Uint8Array(32))
    const wrapped = await wrapKeyBundle(keypairs, wrappingKey)
    const recovered = await unwrapKeyBundle(wrapped, wrappingKey)

    expect(getPublicKey(recovered)).toEqual(getPublicKey(keypairs))

    const store = openKeyStore({ dbName: 'public-api-store' })
    await store.save('alice', recovered)

    const loaded = await store.load('alice')
    expect(loaded).not.toBeNull()
    expect(getPublicKey(loaded!)).toEqual(getPublicKey(keypairs))
  })
})
