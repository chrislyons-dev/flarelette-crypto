# Security Guide — flarelette-crypto

This document covers the threat model, what flarelette-crypto protects against, what it doesn't, and how to deploy it safely. Read it before shipping to production.

---

## What this protects

flarelette-crypto implements hybrid envelope encryption: ML-KEM-1024 (post-quantum) combined with X25519 (classical). An attacker must break **both** simultaneously to recover a channel key.

**Protected against:**

- **Classical network adversary** — passive eavesdropping on stored ciphertext or in-transit encrypted blobs
- **Future quantum adversary** — Shor's algorithm on a large-scale quantum computer can break X25519 but not ML-KEM-1024; classical ML-KEM-1024 analysis shows no known weakness
- **Corrupt server operator** — the server stores ciphertext only; channel keys never leave client devices in plaintext
- **Replay/nonce reuse** — AES-GCM nonces are random per encryption; HMAC-SHA512 binds the nonce to the MAC
- **Ciphertext forgery** — Encrypt-then-MAC: MAC is verified before any decryption attempt; a tampered ciphertext fails the MAC check before the GCM decryption oracle is reached
- **Channel confusion** — `channelId` is bound cryptographically via HKDF info string; an encapsulation from channel A cannot decrypt channel B's content even with the same keypair

**Not protected against:**

- **Compromise of the client device** — private keys live on the device; device compromise exposes them
- **Key exchange interception** — this library handles encryption, not the out-of-band channel you use to exchange public keys; use Signal, verified QR, or equivalent
- **JS-level timing attacks** — JIT and GC make constant-time guarantees hard to enforce in JavaScript; see [JS Side Channels](#js-side-channels)
- **Malicious JS runtime** — a compromised browser or Workers runtime can read any in-memory key material regardless of this library

---

## Cryptographic protocol

### Channel key encapsulation

```
Inputs: channelKey (32B), recipient.mlkem (1568B), recipient.dh (32B), channelId (string)

1. { kemCt, mlkemSs } = ML-KEM-1024.encapsulate(recipient.mlkem)
2. dhEphSk = random 32 bytes
3. dhEphPk = X25519.getPublicKey(dhEphSk)
4. dhSs    = X25519.getSharedSecret(dhEphSk, recipient.dh)
5. wrapKey = HKDF-SHA512(
     ikm  = mlkemSs || dhSs,
     salt = 'flarelette-crypto-v1',
     info = 'channel-key-wrap:' + channelId,
     len  = 32
   )
6. wrapIv     = random 12 bytes
7. wrappedKey = AES-256-GCM(key=wrapKey, iv=wrapIv, plaintext=channelKey)

Output: { kemCt, dhEphemeral: dhEphPk, wrappedKey, wrapIv, channelId }
```

The ephemeral X25519 key (`dhEphSk`) is discarded after encapsulation. Compromise of the recipient's static X25519 secret key does not expose past channel keys (classical forward secrecy for the X25519 half; ML-KEM-1024 has no forward secrecy by design).

### Document encryption

```
Inputs: plaintext (any length), masterKey (32B)

1. encKey     = HKDF-SHA512(masterKey, info='doc-enc-v1')       → 32B
2. macKey     = HKDF-SHA512(masterKey, info='doc-mac-v1')       → 32B
3. nonce      = random 12 bytes
4. ciphertext = AES-256-GCM(key=encKey, iv=nonce, plaintext)    [+ 16B GCM tag]
5. mac        = HMAC-SHA512(key=macKey, message=nonce || ciphertext)

Output: { ciphertext, nonce, mac }
```

Key separation: `encKey` and `macKey` are derived independently from `masterKey` — never used for both cipher and MAC. MAC covers `nonce || ciphertext`; a nonce-swapping attack changes the MAC input and fails.

Decryption verifies the MAC in constant time before attempting AES-GCM decryption. This prevents the GCM decryption oracle from revealing information about the plaintext when the ciphertext has been tampered with.

### Keypair bundle wrapping

Same protocol as document encryption, with `bundle-enc-v1` and `bundle-mac-v1` as HKDF info strings. The 4,800-byte serialized keypair (mlkem_pk || mlkem_sk || dh_pk || dh_sk) is the plaintext.

---

## Audit status

| Component                             | Status                                |
| ------------------------------------- | ------------------------------------- |
| `@noble/curves` (X25519, equalBytes)  | Audited by Cure53 ✅                  |
| `@noble/hashes` (HKDF, HMAC, SHA-512) | Audited by Cure53 ✅                  |
| `@noble/post-quantum` (ML-KEM-1024)   | **Not independently audited** ⚠️      |
| Web Crypto API (AES-GCM)              | Browser/runtime vendor responsibility |
| flarelette-crypto itself              | Not independently audited ⚠️          |

The hybrid design is the primary mitigation for the `@noble/post-quantum` audit gap. If ML-KEM-1024 is broken, X25519 still protects the channel key — an attacker needs to break both.

Monitor [noble/post-quantum releases](https://github.com/paulmillr/noble-post-quantum/releases) for audit announcements. Update `README.md` immediately when an audit lands.

---

## JS side channels

JavaScript provides no hardware-level constant-time guarantees. JIT compilers may optimize branches in ways that introduce timing differences; GC pauses can be observable.

**Mitigations in place:**

- `equalBytes` from `@noble/curves` — the best available JS constant-time comparison, used for all MAC verification
- AES-GCM authentication tag checked by the browser's Web Crypto implementation (typically C code, can be hardware-accelerated)
- MAC verification happens before any decryption — timing on the HMAC compare does not reveal ciphertext structure

**What this means in practice:** flarelette-crypto is not appropriate for environments where a local attacker can make high-frequency timing measurements of MAC verification. For most applications (server-stored encrypted blobs, browser-local encryption) this risk is academic.

---

## Key storage

### v1 (current): raw bytes in IndexedDB

The `openIndexedDBStore()` serializes keypairs to 4,800-byte ArrayBuffers stored in IndexedDB. No encryption at rest. Security depends entirely on the browser's storage isolation (Same-Origin Policy).

**Threat:** A compromised origin (XSS, malicious extension, physical device access) can read IndexedDB directly.

**Mitigation available now:** Use `wrapKeyBundle(keypairs, wrappingKey)` before saving to an IndexedDB store. Derive `wrappingKey` from a user passphrase via Argon2id or scrypt — never pass a raw password string.

```typescript
// Encrypt before storing
const wrappingKey = await argon2id(passphrase, salt) // use a proper KDF library
const bundle = await wrapKeyBundle(keypairs, wrappingKey)
// store bundle as JSON — never store keypairs raw if you need passphrase protection
```

### v2 (planned): WebAuthn PRF

v2 will integrate the [WebAuthn PRF extension](https://w3c.github.io/webauthn/#prf-extension) for hardware-backed key wrapping. The wrapping key will be derived from a hardware authenticator (YubiKey, platform TPM) — extractable only with user presence.

### Cloudflare Workers

Workers use the env adapter (`keypairsFromEnv`). The keypair is stored as a Cloudflare secret — encrypted at rest by Cloudflare, injected into the Worker sandbox at startup. The private key is not accessible via the Cloudflare dashboard after upload.

---

## Key rotation

There is no built-in key rotation mechanism in v1. To rotate:

1. Generate a new keypair with `generateChannelKeypairs()`
2. Re-encapsulate the channel key for all members with the new public key
3. Delete old encapsulations after all members have decapsulated with the new keypair

`ChannelPublicKey.id` (optional) is intended for recipient matching — use it to identify which encapsulation belongs to which member.

---

## Out-of-band key exchange

`exportPublicBundle` / `importPublicBundle` produce ~2,134-character strings. The security of the entire system depends on how you exchange these strings.

**Recommended exchange channels:**

- Signal (verified safety numbers)
- QR code scanned in person
- Verified video call (show the bundle as a QR, verify visually)

**Not recommended:**

- Email (no authentication, trivially MITM-able)
- SMS (SS7 vulnerabilities, carrier access)
- The same app server you're encrypting against (defeats the point)

If you exchange public keys over your own server, the server can substitute its own keys — this is a classic MITM scenario. The security guarantee requires that key exchange happens through a channel your server cannot tamper with.

---

## Deployment checklist

Before shipping to production:

- [ ] Private key stored as a Cloudflare secret (never in `wrangler.toml` vars, never committed)
- [ ] Public key material confirmed correct (verify by running `importPublicBundle` on the stored value)
- [ ] `channelId` values are stable and unique per channel — changing a `channelId` makes existing encapsulations undecryptable
- [ ] Out-of-band key exchange uses a tamper-resistant channel (Signal, QR, video)
- [ ] `wrapKeyBundle` used if storing keypairs in IndexedDB without hardware backing
- [ ] `@noble/post-quantum` audit status checked — update README and this guide if an audit lands
- [ ] Consider whether your threat model requires v2 WebAuthn PRF key wrapping before shipping
