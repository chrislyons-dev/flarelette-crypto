# @chrislyons-dev/flarelette-crypto

Post-quantum hybrid envelope encryption for browsers, Cloudflare Workers, and Node.js.

**ML-KEM-1024 + X25519 · AES-256-GCM · HMAC-SHA512 · Encrypt-then-MAC**

An attacker must break both ML-KEM-1024 (post-quantum, NIST FIPS 203) and X25519 (classical Curve25519) simultaneously to recover a channel key. Breaking one leaves the other intact.

> **Audit status:** `@noble/post-quantum` has not received an independent security audit. The hybrid design mitigates this — if ML-KEM-1024 has bugs, X25519 still protects the channel key. See [Known Limitations](#known-limitations).

---

## What it solves

End-to-end encryption where the server must never see plaintext — documents, messages, files. The server stores ciphertext and acts as an untrusted relay. Key material flows out-of-band (Signal, QR code, secure channel of your choice). Your infrastructure is never a key escrow point.

This is a paranoia layer on top of SSL + OIDC, not a replacement for them.

---

## Install

```bash
npm install @chrislyons-dev/flarelette-crypto
```

Requires Node.js 20+ or a runtime with [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (browsers, Cloudflare Workers).

---

## Quick start

```typescript
import {
  generateChannelKeypairs,
  getPublicKey,
  generateChannelKey,
  encapsulateChannelKey,
  decapsulateChannelKey,
  encryptDoc,
  decryptDoc,
} from '@chrislyons-dev/flarelette-crypto'

// --- Alice generates a keypair and shares her public key out-of-band ---
const aliceKeypairs = generateChannelKeypairs()
const alicePublicKey = getPublicKey(aliceKeypairs)
// Share alicePublicKey via Signal, QR code, etc.

// --- Bob creates a channel and invites Alice ---
const channelKey = generateChannelKey() // 32-byte random key
const channelId = 'channel-abc-123' // stable channel identifier
const encapsulation = await encapsulateChannelKey(channelKey, alicePublicKey, channelId)
// Store encapsulation alongside channel metadata

// --- Alice recovers the channel key and encrypts a document ---
const recovered = await decapsulateChannelKey(encapsulation, aliceKeypairs, channelId)
const plaintext = new TextEncoder().encode('Secret document content')
const encrypted = await encryptDoc(plaintext, recovered)

// --- Alice decrypts later ---
const decrypted = await decryptDoc(encrypted, recovered)
// new TextDecoder().decode(decrypted) === 'Secret document content'
```

---

## Key lifecycle

```
generateChannelKeypairs()          → ChannelKeypairs (opaque, keep secret)
  └─ getPublicKey()                → ChannelPublicKey (safe to share)
  └─ exportPublicBundle()          → "fcpk:hybrid:..."  (wire format for sharing)

importPublicBundle(bundle)         → ChannelPublicKey

generateChannelKey()               → Uint8Array (32B, keep in memory)
  └─ encapsulateChannelKey()       → ChannelEncapsulation (per recipient, storable)
  └─ decapsulateChannelKey()       → Uint8Array (channel key, recovered)
       └─ encryptDoc()             → EncryptedDoc (storable)
       └─ decryptDoc()             → Uint8Array (plaintext)

wrapKeyBundle(keypairs, passKey)   → WrappedBundle (encrypted, JSON-serialisable)
unwrapKeyBundle(bundle, passKey)   → ChannelKeypairs

openKeyStore()                     → KeyStore (IndexedDB in browsers, memory in Workers/Node)
openMemoryStore()                  → KeyStore
openIndexedDBStore(dbName)         → KeyStore
```

---

## API

### Key generation

#### `generateChannelKeypairs(): ChannelKeypairs`

Generate a hybrid ML-KEM-1024 + X25519 keypair. Returns an opaque handle — internal key bytes are not accessible to application code. Use `getPublicKey()` to obtain the shareable public portion and `wrapKeyBundle()` to persist the full keypair.

#### `getPublicKey(keypairs: ChannelKeypairs): ChannelPublicKey`

Extract the public portion. Safe to transmit or store anywhere. Contains only public key material.

---

### Public key sharing

#### `exportPublicBundle(keypairs: ChannelKeypairs): string`

Serialize the public key to a compact string for out-of-band sharing.

```
fcpk:hybrid:<base64url(mlkem_pk [1568B] || dh_pk [32B])>
```

~2,134 characters. Paste it into a form, share via Signal, encode as a QR code.

#### `importPublicBundle(encoded: string): ChannelPublicKey`

Deserialize a public bundle string. Validates the prefix and byte length. Throws on any malformed input — never returns a partial key.

---

### Channel key distribution

#### `encapsulateChannelKey(channelKey, recipient, channelId): Promise<ChannelEncapsulation>`

Wrap a 32-byte channel key for one recipient using hybrid KEM.

- **`channelKey`** — 32-byte random key from `generateChannelKey()`. Never serialised by this library.
- **`recipient`** — `ChannelPublicKey` from `getPublicKey()` or `importPublicBundle()`.
- **`channelId`** — Stable identifier (UUID, database row ID). Bound cryptographically into the KEM output — a `ChannelEncapsulation` from channel A cannot be used for channel B, even with the same keypair.

Call once per recipient. Pass the same `channelKey` for all recipients in a channel.

#### `decapsulateChannelKey(encapsulation, keypairs, channelId): Promise<Uint8Array>`

Recover the channel key from a `ChannelEncapsulation`. Returns the 32-byte channel key.

Throws if `channelId` doesn't match, the keypair doesn't match, or the encapsulation is corrupt. Channel binding is enforced cryptographically via HKDF — not a runtime string check.

---

### Document encryption

#### `encryptDoc(plaintext, masterKey): Promise<EncryptedDoc>`

Encrypt arbitrary bytes with a 32-byte channel key.

Protocol — Encrypt-then-MAC:

1. `encKey = HKDF-SHA512(masterKey, 'doc-enc-v1')` — 32B AES key
2. `macKey = HKDF-SHA512(masterKey, 'doc-mac-v1')` — 32B HMAC key
3. `nonce = random 12 bytes`
4. `ciphertext = AES-256-GCM(encKey, nonce, plaintext)` (includes 16B GCM tag)
5. `mac = HMAC-SHA512(macKey, nonce || ciphertext)`

Key separation (distinct `encKey` and `macKey`) and MAC-before-decrypt prevent GCM oracle attacks.

#### `decryptDoc(doc, masterKey): Promise<Uint8Array>`

Verify the HMAC-SHA512 MAC in constant time, then AES-GCM decrypt. Throws immediately on MAC failure — no partial decryption, no timing oracle.

---

### Keypair persistence

#### `wrapKeyBundle(keypairs, wrappingKey): Promise<WrappedBundle>`

Encrypt a keypair for at-rest storage. Uses the same Encrypt-then-MAC protocol as `encryptDoc()`, with distinct HKDF info strings (`bundle-enc-v1`, `bundle-mac-v1`).

- **`wrappingKey`** — at least 32 bytes. Derive from a user passphrase via Argon2id/scrypt — never pass a raw password string.

Returns a `WrappedBundle` with base64url string fields — directly JSON-serialisable for IndexedDB or R2 storage.

#### `unwrapKeyBundle(wrapped, wrappingKey): Promise<ChannelKeypairs>`

Verify MAC and decrypt. Throws on MAC failure, wrong key, or corrupt data.

#### `openKeyStore(options?): KeyStore`

Return the best available `KeyStore` for the runtime:

- IndexedDB if `indexedDB` is defined (browsers)
- In-memory `Map` otherwise (Cloudflare Workers, Node.js)

#### `openMemoryStore(): KeyStore`

In-memory store backed by a `Map`. No serialization overhead. Data does not survive process restarts.

#### `openIndexedDBStore(dbName?): KeyStore`

IndexedDB-backed store. Serializes keypairs to 4,800-byte ArrayBuffers. Default DB name: `'flarelette-crypto'`.

**v1 limitation:** raw serialized bytes, no encryption. Use `wrapKeyBundle()` separately if you need encryption at rest.

---

## Cloudflare Workers adapter

Workers don't have IndexedDB. Load a keypair from Worker env bindings instead.

**1. Generate a keypair:**

```bash
npx flarelette-crypto-keygen --alg=hybrid --dotenv
```

Output:

```
# flarelette-crypto keypair — ML-KEM-1024 + X25519
# Store FLARELETTE_CRYPTO_KEYPAIR_SK as a Cloudflare secret:
#   wrangler secret put FLARELETTE_CRYPTO_KEYPAIR_SK
# FLARELETTE_CRYPTO_KEYPAIR_PK can go in [vars] in wrangler.toml
FLARELETTE_CRYPTO_KEYPAIR_SK=fcsk:hybrid:<base64url>
FLARELETTE_CRYPTO_KEYPAIR_PK=fcpk:hybrid:<base64url>
```

**2. Store the secret key:**

```bash
wrangler secret put FLARELETTE_CRYPTO_KEYPAIR_SK
```

**3. Add the public key to `wrangler.toml`:**

```toml
[vars]
FLARELETTE_CRYPTO_KEYPAIR_PK = "fcpk:hybrid:..."
```

**4. Load in your Worker:**

```typescript
import { keypairsFromEnv } from '@chrislyons-dev/flarelette-crypto/adapters/workers'

export default {
  async fetch(request: Request, env: Env) {
    const keypairs = keypairsFromEnv(env)
    // use keypairs for encapsulation or decapsulation
  },
}
```

Supports `_NAME` indirection for named secret bindings:

```toml
[vars]
FLARELETTE_CRYPTO_KEYPAIR_SK_NAME = "MY_CUSTOM_BINDING"
```

---

## CLI keygen

```bash
npx flarelette-crypto-keygen [--alg=hybrid] [--dotenv]
```

| Flag           | Description                                   |
| -------------- | --------------------------------------------- |
| `--alg=hybrid` | Algorithm (only `hybrid` supported)           |
| `--dotenv`     | Output in `.env` format with deployment notes |

Without `--dotenv`, outputs JSON:

```json
{
  "sk": "fcsk:hybrid:...",
  "pk": "fcpk:hybrid:..."
}
```

---

## Platform compatibility

| Feature                     | Browser | Cloudflare Workers | Node.js 20+ |
| --------------------------- | ------- | ------------------ | ----------- |
| `generateChannelKeypairs`   | ✅      | ✅                 | ✅          |
| `encapsulateChannelKey`     | ✅      | ✅                 | ✅          |
| `decapsulateChannelKey`     | ✅      | ✅                 | ✅          |
| `encryptDoc` / `decryptDoc` | ✅      | ✅                 | ✅          |
| `openIndexedDBStore`        | ✅      | ❌                 | ❌          |
| `openMemoryStore`           | ✅      | ✅                 | ✅          |
| `keypairsFromEnv`           | ❌      | ✅                 | ✅          |

Requires `globalThis.crypto` (Web Crypto API). All modern browsers, Cloudflare Workers, and Node.js 20+ provide this.

---

## Types

```typescript
// Opaque — internal structure not part of the public contract
class ChannelKeypairs { ... }

// Public portion — safe to share out-of-band
interface ChannelPublicKey {
  id?: string       // optional human identifier (email, username, device name)
  mlkem: Uint8Array // ML-KEM-1024 public key — 1,568 bytes
  dh: Uint8Array    // X25519 public key — 32 bytes
}

// Per-recipient KEM output — store alongside channel membership metadata
interface ChannelEncapsulation {
  recipientId?: string
  channelId: string
  kemCt: Uint8Array       // ML-KEM-1024 ciphertext — 1,568 bytes
  dhEphemeral: Uint8Array // ephemeral X25519 public key — 32 bytes
  wrappedKey: Uint8Array  // channel key encrypted with KEM-derived wrap key
  wrapIv: Uint8Array      // 12-byte GCM nonce
}

// Per-document Encrypt-then-MAC output
interface EncryptedDoc {
  ciphertext: Uint8Array // AES-256-GCM output (includes 16B GCM tag)
  nonce: Uint8Array      // 12-byte random GCM nonce
  mac: Uint8Array        // HMAC-SHA512 over nonce || ciphertext
}

// Encrypted keypair bundle — JSON-serialisable
interface WrappedBundle {
  ciphertext: string // base64url
  nonce: string      // base64url
  mac: string        // base64url
}

interface KeyStore {
  save(name: string, keypairs: ChannelKeypairs): Promise<void>
  load(name: string): Promise<ChannelKeypairs | null>
  list(): Promise<string[]>
  delete(name: string): Promise<void>
}
```

---

## Known limitations

**State these clearly before deploying:**

1. **`@noble/post-quantum` is not independently audited.** The hybrid design mitigates this — X25519 remains intact if ML-KEM-1024 has a bug. The Noble team plans an audit. Check the [noble/post-quantum repository](https://github.com/paulmillr/noble-post-quantum) for current status.

2. **IndexedDB key storage (`v1`) is raw bytes.** No device-key wrapping or hardware-backed storage. Keys are as secure as the device they're stored on. v2 will integrate WebAuthn PRF for hardware-backed wrapping.

3. **No JS-level side-channel guarantees.** JIT compilation and garbage collection make constant-time guarantees hard in JavaScript. `equalBytes` from `@noble/curves` is the best available mitigation, not a solved problem.

4. **Out-of-band key exchange is your responsibility.** This library handles encryption — not the secure channel you use to exchange public keys. Use Signal, a verified QR code scan, or equivalent.

5. **This is not a replacement for SSL + OIDC.** It's an additional layer for content that must remain private from the server operator.

See [security-guide.md](https://github.com/chrislyons-dev/flarelette-crypto/blob/main/docs/security-guide.md) for the full threat model.

---

## License

MIT
