/**
 * Base64url encode / decode.
 *
 * Uses btoa/atob — available in browsers, Cloudflare Workers, and Node.js 20+.
 * No imports, no dependencies.
 */

/**
 * Encode bytes to a base64url string (no padding).
 */
export function base64urlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 * Decode a base64url string to bytes.
 *
 * Accepts strings with or without padding. Throws on non-base64url characters.
 */
export function base64urlDecode(s: string): Uint8Array {
  const padded = s
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(s.length / 4) * 4, '=')
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
