import { describe, it, expect } from 'vitest'
import { generateChannelKeypairs, getPublicKey } from '../src/kem.js'
import { exportPublicBundle, importPublicBundle } from '../src/serialize.js'
import { base64urlEncode } from '../src/codec.js'
import { MLKEM_PUBLIC_KEY_BYTES, DH_KEY_BYTES } from '../src/kem.js'

const PREFIX = 'fcpk:hybrid:'
const TOTAL_BYTES = MLKEM_PUBLIC_KEY_BYTES + DH_KEY_BYTES // 1600

describe('exportPublicBundle', () => {
  it('returns a string with the fcpk:hybrid: prefix', () => {
    const kp = generateChannelKeypairs()
    const bundle = exportPublicBundle(kp)
    expect(bundle.startsWith(PREFIX)).toBe(true)
  })

  it('payload decodes to exactly 1600 bytes', () => {
    const kp = generateChannelKeypairs()
    const bundle = exportPublicBundle(kp)
    const payload = bundle.slice(PREFIX.length)
    // base64url: each char represents 6 bits; 1600 bytes → ceil(1600*4/3) chars without padding
    // We can verify length is consistent: decode and check
    const decoded = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    expect(decoded.length).toBe(TOTAL_BYTES)
  })

  it('two calls produce different encodings (public keys are random)', () => {
    const kp1 = generateChannelKeypairs()
    const kp2 = generateChannelKeypairs()
    expect(exportPublicBundle(kp1)).not.toBe(exportPublicBundle(kp2))
  })
})

describe('importPublicBundle — round-trip', () => {
  it('round-trip: importPublicBundle(exportPublicBundle(kp)) equals getPublicKey(kp)', () => {
    const kp = generateChannelKeypairs()
    const bundle = exportPublicBundle(kp)
    const recovered = importPublicBundle(bundle)
    const expected = getPublicKey(kp)

    expect(recovered.mlkem).toEqual(expected.mlkem)
    expect(recovered.dh).toEqual(expected.dh)
  })

  it('round-trip preserves mlkem key (1568 bytes)', () => {
    const kp = generateChannelKeypairs()
    const recovered = importPublicBundle(exportPublicBundle(kp))
    expect(recovered.mlkem.length).toBe(MLKEM_PUBLIC_KEY_BYTES)
  })

  it('round-trip preserves dh key (32 bytes)', () => {
    const kp = generateChannelKeypairs()
    const recovered = importPublicBundle(exportPublicBundle(kp))
    expect(recovered.dh.length).toBe(DH_KEY_BYTES)
  })
})

describe('importPublicBundle — invalid input rejection', () => {
  it('throws on unknown prefix', () => {
    expect(() => importPublicBundle('wrong:prefix:abc')).toThrow('prefix')
  })

  it('throws on empty string', () => {
    expect(() => importPublicBundle('')).toThrow('prefix')
  })

  it('throws when payload decodes to too few bytes (truncated)', () => {
    // Encode only 100 bytes (instead of 1600)
    const short = PREFIX + base64urlEncode(new Uint8Array(100))
    expect(() => importPublicBundle(short)).toThrow(`expected ${TOTAL_BYTES} bytes`)
  })

  it('throws when payload decodes to too many bytes (extra data)', () => {
    // Encode 1601 bytes (one extra)
    const long = PREFIX + base64urlEncode(new Uint8Array(TOTAL_BYTES + 1))
    expect(() => importPublicBundle(long)).toThrow(`expected ${TOTAL_BYTES} bytes`)
  })

  it('throws when payload is exactly 0 bytes', () => {
    const empty = PREFIX + base64urlEncode(new Uint8Array(0))
    expect(() => importPublicBundle(empty)).toThrow(`expected ${TOTAL_BYTES} bytes`)
  })
})
