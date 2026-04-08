import { describe, expect, it } from 'vitest'
import {
  keypairsFromEnv,
  keypairsToEnvVars,
} from '@chrislyons-dev/flarelette-crypto/adapters/workers'
import {
  decapsulateChannelKey,
  encapsulateChannelKey,
  generateChannelKey,
  generateChannelKeypairs,
  getPublicKey,
} from '@chrislyons-dev/flarelette-crypto'

describe('public workers adapter API', () => {
  it('round-trips keypairs through env bindings using only public imports', async () => {
    const original = generateChannelKeypairs()
    const env = keypairsToEnvVars(original)
    const loaded = keypairsFromEnv(env)

    expect(getPublicKey(loaded)).toEqual(getPublicKey(original))

    const channelKey = generateChannelKey()
    const channelId = 'public-workers-channel'
    const encapsulation = await encapsulateChannelKey(
      channelKey,
      getPublicKey(original),
      channelId
    )

    await expect(
      decapsulateChannelKey(encapsulation, loaded, channelId)
    ).resolves.toEqual(channelKey)
  })
})
