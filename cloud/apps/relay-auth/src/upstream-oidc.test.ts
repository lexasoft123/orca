import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { exportJWK, generateKeyPair, SignJWT, createLocalJWKSet, jwtVerify } from 'jose'
import { expect, it } from 'vitest'
import { createService } from './service.js'

it('authenticates upstream users and rejects invalid identity tokens and state', async () => {
  const key = await generateKeyPair('ES256')
  const jwk = { ...await exportJWK(key.publicKey), kid: 'provider', alg: 'ES256' }
  let issuer = '', nonce = '', variant = 'valid'
  const server = createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json')
    if (req.url === '/.well-known/openid-configuration') return res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/keys` }))
    if (req.url === '/keys') return res.end(JSON.stringify({ keys: [jwk] }))
    if (req.url === '/token') {
      const claims = { nonce: variant === 'nonce' ? 'wrong' : nonce, email: variant === 'email' ? 'other@example.com' : variant === 'domain' ? 'alice@wrong.test' : 'alice@example.com', email_verified: variant !== 'unverified', name: 'Alice' }
      let idToken = await new SignJWT(claims).setProtectedHeader({ alg: 'ES256', kid: 'provider' }).setIssuer(variant === 'issuer' ? 'https://wrong.example' : issuer).setAudience(variant === 'audience' ? 'wrong' : 'desktop-provider').setSubject('alice').setIssuedAt().setExpirationTime(variant === 'expired' ? '1 second ago' : '5 minutes').sign(key.privateKey)
      if (variant === 'none') idToken = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${idToken.split('.')[1]}.`
      return res.end(JSON.stringify({ id_token: idToken }))
    }
    res.statusCode = 404; res.end('{}')
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('missing address')
  issuer = `http://127.0.0.1:${address.port}`
  const dir = mkdtempSync(join(tmpdir(), 'upstream-auth-'))
  const service = await createService({ issuer: 'https://auth.example', clientId: 'desktop', secret: '', email: '', userId: 'admin', dataDir: dir, upstream: { issuer, clientId: 'desktop-provider', allowedEmails: ['alice@example.com'], allowedDomains: ['allowed.test'] } })
  try {
    const verifier = 'a'.repeat(43), redirectUri = 'http://127.0.0.1:1234/auth/callback'
    const query = new URLSearchParams({ client_id: 'desktop', response_type: 'code', redirect_uri: redirectUri, nonce: 'desktop-nonce', state: 'desktop-state', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', local_profile_id: 'local' })
    const post = (path: string, data: object, access?: string) => service.app.request(`/v1/desktop/auth/${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(access ? { authorization: `Bearer ${access}` } : {}) }, body: JSON.stringify(data) })
    const start = async () => { const response = await service.app.request(`/v1/desktop/auth/authorize?${query}`); expect(response.status).toBe(303); const url = new URL(response.headers.get('location')!); nonce = url.searchParams.get('nonce')!; return url.searchParams.get('state')! }
    const callback = (state: string) => service.app.request(`/v1/desktop/auth/upstream/callback?${new URLSearchParams({ state, code: 'provider-code' })}`)
    const state = await start(), login = await callback(state)
    expect(login.status).toBe(303)
    expect((await callback(state)).status).toBe(401)
    const code = new URL(login.headers.get('location')!).searchParams.get('code')
    const session = await (await post('session', { code, codeVerifier: verifier, nonce: 'desktop-nonce', state: 'desktop-state', redirectUri, localProfileId: 'local' })).json() as { accessToken: string; refreshToken: string; cloud: { userId: string; email: string; cloudProfileId: string } }
    const expectedUser = `${createHash('sha256').update(issuer).digest('base64url')}:alice`
    expect(session.cloud).toMatchObject({ userId: expectedUser, email: 'alice@example.com' })
    const hostKey = Buffer.alloc(32), host = createHash('sha256').update(hostKey).digest('base64url').slice(0, 16)
    const minted = await (await post('relay-token', { relayHostId: host, hostPublicKeyB64: hostKey.toString('base64') }, session.accessToken)).json() as { relayToken: string }
    const keys = await (await service.app.request('/.well-known/jwks.json')).json() as { keys: [] }
    expect((await jwtVerify(minted.relayToken, createLocalJWKSet(keys))).payload).toMatchObject({ sub: expectedUser, prof: session.cloud.cloudProfileId })
    const refreshed = await (await post('refresh', { refreshToken: session.refreshToken })).json() as typeof session
    expect(refreshed.cloud.userId).toBe(expectedUser)
    const profile = await (await post('profile', { refreshToken: refreshed.refreshToken }, refreshed.accessToken)).json() as typeof session
    expect(profile.cloud).toMatchObject({ userId: expectedUser, email: 'alice@example.com', displayName: 'Alice' })
    for (variant of ['nonce', 'audience', 'issuer', 'expired', 'unverified', 'email', 'domain', 'none']) expect((await callback(await start())).status).toBe(401)
    expect((await callback('tampered')).status).toBe(401)
  } finally { service.close(); server.close(); rmSync(dir, { recursive: true, force: true }) }
})
