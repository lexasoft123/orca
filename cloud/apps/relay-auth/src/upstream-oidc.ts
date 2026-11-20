import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose'
import { z } from 'zod'

export type UpstreamConfig = { issuer: string; clientId: string; clientSecret?: string; allowedEmails?: string[]; allowedDomains?: string[]; keepSecretLogin?: boolean }
const documentSchema = z.object({ issuer: z.string(), authorization_endpoint: z.string().url(), token_endpoint: z.string().url(), jwks_uri: z.string().url(), userinfo_endpoint: z.string().url().optional() })

export function upstreamOidc(config: UpstreamConfig, callback: string) {
  let cache: { document: z.infer<typeof documentSchema>; expires: number } | undefined
  function validateEndpoint(url: string) {
    const target = new URL(url)
    const issuer = new URL(config.issuer)
    if (target.protocol !== 'https:' && !(issuer.protocol === 'http:' && target.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(target.hostname))) throw new Error('invalid upstream endpoint')
  }
  async function json(url: string, init: RequestInit = {}) {
    validateEndpoint(url)
    const response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(5000) })
    if (!response.ok || !response.body) throw new Error('upstream request failed')
    const reader = response.body.getReader(), chunks: Uint8Array[] = []
    let size = 0
    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        size += value.length
        if (size > 65536) { await reader.cancel(); throw new Error('upstream response too large') }
        chunks.push(value)
      }
    } finally { reader.releaseLock() }
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
  }
  async function discovery() {
    if (cache && cache.expires > Date.now()) return cache.document
    const document = documentSchema.parse(await json(`${config.issuer}/.well-known/openid-configuration`))
    if (document.issuer !== config.issuer) throw new Error('issuer mismatch')
    for (const endpoint of [document.authorization_endpoint, document.token_endpoint, document.jwks_uri, document.userinfo_endpoint]) if (endpoint) validateEndpoint(endpoint)
    cache = { document, expires: Date.now() + 300_000 }
    return document
  }
  return {
    async authorize(state: string, nonce: string, challenge: string) {
      const url = new URL((await discovery()).authorization_endpoint)
      for (const [key, value] of Object.entries({ client_id: config.clientId, response_type: 'code', redirect_uri: callback, scope: 'openid email profile', state, nonce, code_challenge: challenge, code_challenge_method: 'S256' })) url.searchParams.set(key, value)
      return url.toString()
    },
    async exchange(code: string, verifier: string, nonce: string) {
      const document = await discovery()
      const params = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: callback, client_id: config.clientId, code_verifier: verifier })
      if (config.clientSecret) params.set('client_secret', config.clientSecret)
      const result = z.object({ id_token: z.string(), access_token: z.string().optional() }).parse(await json(document.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: params }))
      const jwks = z.object({ keys: z.array(z.record(z.string(), z.unknown())) }).parse(await json(document.jwks_uri)) as JSONWebKeySet
      const { payload } = await jwtVerify(result.id_token, createLocalJWKSet(jwks), { issuer: config.issuer, audience: config.clientId, algorithms: ['RS256', 'ES256', 'EdDSA'], requiredClaims: ['sub', 'exp', 'iat'] })
      if (payload.nonce !== nonce || payload.email_verified === false || !payload.sub) throw new Error('invalid identity')
      let claims = payload
      if ((!payload.email || !payload.name) && document.userinfo_endpoint && result.access_token) {
        const userinfo = z.object({ sub: z.string(), email: z.string().optional(), email_verified: z.boolean().optional(), name: z.string().optional() }).parse(await json(document.userinfo_endpoint, { headers: { authorization: `Bearer ${result.access_token}` } }))
        if (userinfo.sub !== payload.sub || userinfo.email_verified === false) throw new Error('invalid userinfo')
        claims = { ...userinfo, ...payload, email: payload.email ?? userinfo.email, name: payload.name ?? userinfo.name }
      }
      if (typeof claims.email !== 'string' || !claims.email) throw new Error('missing email')
      const email = claims.email.toLowerCase()
      const emails = config.allowedEmails ?? [], domains = config.allowedDomains ?? []
      if ((emails.length || domains.length) && !emails.includes(email) && !domains.includes(email.split('@').at(-1) ?? '')) throw new Error('identity not allowed')
      return { userId: `${Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(config.issuer))).toString('base64url')}:${payload.sub}`, email: claims.email, name: typeof claims.name === 'string' ? claims.name : '' }
    }
  }
}
