import { describe, it, expect } from 'vitest'
import { keypairsToEnvVars, keypairsFromEnv } from '../src/adapters/workers.js'
import { generateChannelKeypairs, getPublicKey } from '../src/kem.js'
import {
  generateChannelKey,
  encapsulateChannelKey,
  decapsulateChannelKey,
} from '../src/channel.js'
import { base64urlDecode } from '../src/codec.js'
import { MLKEM_SECRET_KEY_BYTES, DH_KEY_BYTES } from '../src/kem.js'

const SK_PREFIX = 'fcsk:hybrid:'
const PK_PREFIX = 'fcpk:hybrid:'
const SK_PAYLOAD_BYTES = MLKEM_SECRET_KEY_BYTES + DH_KEY_BYTES // 3200

// ---------------------------------------------------------------------------
// keypairsToEnvVars
// ---------------------------------------------------------------------------

describe('keypairsToEnvVars', () => {
  it('returns an SK with the fcsk:hybrid: prefix', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_SK } = keypairsToEnvVars(kp)
    expect(FLARELETTE_CRYPTO_KEYPAIR_SK.startsWith(SK_PREFIX)).toBe(true)
  })

  it('returns a PK with the fcpk:hybrid: prefix', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_PK } = keypairsToEnvVars(kp)
    expect(FLARELETTE_CRYPTO_KEYPAIR_PK.startsWith(PK_PREFIX)).toBe(true)
  })

  it('SK payload decodes to 3200 bytes (mlkem_sk || dh_sk)', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_SK } = keypairsToEnvVars(kp)
    const payload = base64urlDecode(
      FLARELETTE_CRYPTO_KEYPAIR_SK.slice(SK_PREFIX.length)
    )
    expect(payload.length).toBe(SK_PAYLOAD_BYTES)
  })

  it('SK prefix portion (mlkem_sk) is 3168 bytes', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_SK } = keypairsToEnvVars(kp)
    const payload = base64urlDecode(
      FLARELETTE_CRYPTO_KEYPAIR_SK.slice(SK_PREFIX.length)
    )
    expect(payload.slice(0, MLKEM_SECRET_KEY_BYTES).length).toBe(MLKEM_SECRET_KEY_BYTES)
  })

  it('two keypairs produce different SK values', () => {
    const kp1 = generateChannelKeypairs()
    const kp2 = generateChannelKeypairs()
    const sk1 = keypairsToEnvVars(kp1).FLARELETTE_CRYPTO_KEYPAIR_SK
    const sk2 = keypairsToEnvVars(kp2).FLARELETTE_CRYPTO_KEYPAIR_SK
    expect(sk1).not.toBe(sk2)
  })
})

// ---------------------------------------------------------------------------
// keypairsFromEnv — round-trip
// ---------------------------------------------------------------------------

describe('keypairsFromEnv — round-trip', () => {
  it('recovers keypairs that produce the same public key', () => {
    const original = generateChannelKeypairs()
    const env = keypairsToEnvVars(original)
    const loaded = keypairsFromEnv(env)

    const pubOriginal = getPublicKey(original)
    const pubLoaded = getPublicKey(loaded)

    expect(pubLoaded.mlkem).toEqual(pubOriginal.mlkem)
    expect(pubLoaded.dh).toEqual(pubOriginal.dh)
  })

  it('functional proof: recovered keypairs can decapsulate a channel key', async () => {
    const original = generateChannelKeypairs()
    const env = keypairsToEnvVars(original)
    const loaded = keypairsFromEnv(env)

    const channelKey = generateChannelKey()
    const channelId = 'workers-adapter-test'
    const enc = await encapsulateChannelKey(
      channelKey,
      getPublicKey(original),
      channelId
    )
    const recovered = await decapsulateChannelKey(enc, loaded, channelId)

    expect(recovered).toEqual(channelKey)
  })
})

// ---------------------------------------------------------------------------
// keypairsFromEnv — _NAME indirection
// ---------------------------------------------------------------------------

describe('keypairsFromEnv — _NAME indirection', () => {
  it('reads SK from the named binding when _NAME is set', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_SK, FLARELETTE_CRYPTO_KEYPAIR_PK } =
      keypairsToEnvVars(kp)

    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_SK_NAME: 'MY_SECRET',
      MY_SECRET: FLARELETTE_CRYPTO_KEYPAIR_SK,
      FLARELETTE_CRYPTO_KEYPAIR_PK,
    }

    const loaded = keypairsFromEnv(env)
    expect(getPublicKey(loaded).mlkem).toEqual(getPublicKey(kp).mlkem)
  })

  it('reads PK from the named binding when _NAME is set', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_SK, FLARELETTE_CRYPTO_KEYPAIR_PK } =
      keypairsToEnvVars(kp)

    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_SK,
      FLARELETTE_CRYPTO_KEYPAIR_PK_NAME: 'MY_PUBLIC',
      MY_PUBLIC: FLARELETTE_CRYPTO_KEYPAIR_PK,
    }

    const loaded = keypairsFromEnv(env)
    expect(getPublicKey(loaded).dh).toEqual(getPublicKey(kp).dh)
  })

  it('both _NAME indirections together', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_SK, FLARELETTE_CRYPTO_KEYPAIR_PK } =
      keypairsToEnvVars(kp)

    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_SK_NAME: 'SEC',
      SEC: FLARELETTE_CRYPTO_KEYPAIR_SK,
      FLARELETTE_CRYPTO_KEYPAIR_PK_NAME: 'PUB',
      PUB: FLARELETTE_CRYPTO_KEYPAIR_PK,
    }

    const loaded = keypairsFromEnv(env)
    expect(getPublicKey(loaded).mlkem).toEqual(getPublicKey(kp).mlkem)
  })
})

// ---------------------------------------------------------------------------
// keypairsFromEnv — error handling
// ---------------------------------------------------------------------------

describe('keypairsFromEnv — missing env vars', () => {
  it('throws a helpful message when SK is missing', () => {
    const kp = generateChannelKeypairs()
    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_PK: keypairsToEnvVars(kp).FLARELETTE_CRYPTO_KEYPAIR_PK,
    }
    expect(() => keypairsFromEnv(env)).toThrow('FLARELETTE_CRYPTO_KEYPAIR_SK')
  })

  it('throws a helpful message when PK is missing', () => {
    const kp = generateChannelKeypairs()
    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_SK: keypairsToEnvVars(kp).FLARELETTE_CRYPTO_KEYPAIR_SK,
    }
    expect(() => keypairsFromEnv(env)).toThrow('FLARELETTE_CRYPTO_KEYPAIR_PK')
  })

  it('throws when env is empty', () => {
    expect(() => keypairsFromEnv({})).toThrow('FLARELETTE_CRYPTO_KEYPAIR_SK')
  })
})

describe('keypairsFromEnv — malformed input', () => {
  it('throws on wrong SK prefix', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_PK } = keypairsToEnvVars(kp)
    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_SK: 'wrong:prefix:abc',
      FLARELETTE_CRYPTO_KEYPAIR_PK,
    }
    expect(() => keypairsFromEnv(env)).toThrow('prefix')
  })

  it('throws when SK payload is too short (truncated)', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_PK } = keypairsToEnvVars(kp)
    // Build a valid prefix but with only 100 bytes of payload
    const short = Buffer.from(new Uint8Array(100)).toString('base64url')
    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_SK: `fcsk:hybrid:${short}`,
      FLARELETTE_CRYPTO_KEYPAIR_PK,
    }
    expect(() => keypairsFromEnv(env)).toThrow(`expected ${SK_PAYLOAD_BYTES} bytes`)
  })

  it('throws when PK prefix is wrong (delegates to importPublicBundle)', () => {
    const kp = generateChannelKeypairs()
    const { FLARELETTE_CRYPTO_KEYPAIR_SK } = keypairsToEnvVars(kp)
    const env = {
      FLARELETTE_CRYPTO_KEYPAIR_SK,
      FLARELETTE_CRYPTO_KEYPAIR_PK: 'fcwrong:hybrid:abc',
    }
    expect(() => keypairsFromEnv(env)).toThrow('prefix')
  })
})
