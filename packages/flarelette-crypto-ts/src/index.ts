/**
 * flarelette-crypto — post-quantum hybrid envelope encryption.
 *
 * Public API. Import from '@chrislyons-dev/flarelette-crypto'.
 * Do not import from internal modules (kem.ts, channel.ts, etc.) directly —
 * their APIs are not stable and may change without notice.
 *
 * Quickstart:
 *
 *   // Alice generates a keypair
 *   const aliceKeypairs = generateChannelKeypairs()
 *   const alicePublicKey = getPublicKey(aliceKeypairs)
 *
 *   // Bob creates a channel and invites Alice
 *   const channelKey = generateChannelKey()
 *   const encapsulation = await encapsulateChannelKey(channelKey, alicePublicKey, channelId)
 *
 *   // Alice recovers the channel key and decrypts a document
 *   const channelKey = await decapsulateChannelKey(encapsulation, aliceKeypairs, channelId)
 *   const doc = await encryptDoc(plaintext, channelKey)
 *   const plaintext = await decryptDoc(doc, channelKey)
 */

// Types — public contract
export type {
  ChannelPublicKey,
  ChannelEncapsulation,
  EncryptedDoc,
  WrappedBundle,
} from './types.js'
export { ChannelKeypairs } from './types.js'

// Key lifecycle
export { generateChannelKeypairs, getPublicKey } from './kem.js'

// Channel key — generate in the browser, distribute via encapsulateChannelKey
export { generateChannelKey } from './channel.js'

// Channel key distribution — KEM layer (run once per channel membership change)
export { encapsulateChannelKey, decapsulateChannelKey } from './channel.js'

// Document encryption — symmetric layer (run per document / message)
export { encryptDoc, decryptDoc } from './doc.js'

// Keypair persistence — wrap/unwrap and KeyStore implementations
export {
  wrapKeyBundle,
  unwrapKeyBundle,
  openKeyStore,
  openMemoryStore,
  openIndexedDBStore,
} from './store.js'
export type { KeyStore } from './store.js'

// Public key serialization for out-of-band sharing
export { exportPublicBundle, importPublicBundle } from './serialize.js'
