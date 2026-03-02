/**
 * Core types for flarelette-crypto.
 *
 * ChannelKeypairs is intentionally opaque — treat it as a handle, not a data bag.
 * Its internal layout may change between versions. Access it only via the exported
 * functions (generateChannelKeypairs, encapsulateChannelKey, wrapKeyBundle, etc.).
 */

// ---------------------------------------------------------------------------
// Internal representation — not part of the public contract
// ---------------------------------------------------------------------------

/** @internal */
export interface KeypairInternal {
  mlkem: { publicKey: Uint8Array; secretKey: Uint8Array }
  dh: { publicKey: Uint8Array; secretKey: Uint8Array }
}

// WeakMap stores internal data without exposing it on the object
const _keypairStore = new WeakMap<ChannelKeypairs, KeypairInternal>()

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * An opaque handle wrapping a hybrid ML-KEM-1024 + X25519 keypair.
 *
 * Create via generateChannelKeypairs(). Persist via wrapKeyBundle()/unwrapKeyBundle().
 * Do not inspect or construct directly — internal layout is not guaranteed.
 */
export class ChannelKeypairs {
  /** @internal */
  constructor(internal: KeypairInternal) {
    _keypairStore.set(this, internal)
  }
}

/** @internal — used by kem.ts, channel.ts, store.ts */
export function _getKeypairInternal(kp: ChannelKeypairs): KeypairInternal {
  const data = _keypairStore.get(kp)
  if (data === undefined) throw new Error('Invalid ChannelKeypairs instance')
  return data
}

/**
 * The public portion of a channel keypair — safe to share out-of-band (e.g. via Signal).
 *
 * Obtain via getPublicKey(keypairs) or importPublicBundle(encoded) (Phase 2).
 */
export interface ChannelPublicKey {
  /** Optional human-readable identifier (email, username, device name). */
  id?: string
  /** ML-KEM-1024 public key — 1,568 bytes. */
  mlkem: Uint8Array
  /** X25519 public key — 32 bytes. */
  dh: Uint8Array
}

/**
 * Per-recipient KEM output from encapsulateChannelKey().
 *
 * Store this alongside channel membership metadata. One entry per recipient.
 * All byte arrays serialise to base64url strings for JSON/R2 storage.
 */
export interface ChannelEncapsulation {
  /** Matches the recipient's ChannelPublicKey.id, if set. */
  recipientId?: string
  /** The channel ID this encapsulation is bound to. */
  channelId: string
  /** ML-KEM-1024 KEM ciphertext — 1,568 bytes. */
  kemCt: Uint8Array
  /** Ephemeral X25519 public key — 32 bytes. */
  dhEphemeral: Uint8Array
  /** Channel key encrypted with the derived wrap key — 32 + 16 bytes (GCM tag). */
  wrappedKey: Uint8Array
  /** 12-byte random IV for AES-GCM key wrapping. */
  wrapIv: Uint8Array
}

/**
 * Per-document symmetric encryption output from encryptDoc().
 *
 * Encrypted with AES-256-GCM; authenticated with HMAC-SHA512 (Encrypt-then-MAC).
 * The MAC is computed over the ciphertext; decryptDoc() verifies it before decrypting.
 */
export interface EncryptedDoc {
  /** AES-256-GCM ciphertext (includes 16-byte GCM auth tag). */
  ciphertext: Uint8Array
  /** 12-byte random GCM nonce. */
  nonce: Uint8Array
  /** HMAC-SHA512 over the ciphertext — verified before any decryption attempt. */
  mac: Uint8Array
}

/**
 * A keypair bundle encrypted for at-rest storage (e.g. IndexedDB).
 *
 * Produced by wrapKeyBundle(), consumed by unwrapKeyBundle(). All fields
 * are base64url strings so this is directly JSON-serialisable.
 */
export interface WrappedBundle {
  /** AES-256-GCM ciphertext of the serialised keypair — base64url. */
  ciphertext: string
  /** 12-byte GCM nonce — base64url. */
  nonce: string
  /** HMAC-SHA512 over the ciphertext — base64url. */
  mac: string
}
