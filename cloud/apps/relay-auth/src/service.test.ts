import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { createLocalJWKSet, jwtVerify } from 'jose'
import { expect, it } from 'vitest'
import { createService } from './service.js'

it('mints a relay token verifiable with JWKS and revokes a reused refresh family', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'relay-auth-'))
  const service = await createService({ issuer: 'https://auth.example', clientId: 'orca-desktop', secret: 'a'.repeat(32), email: 'admin@example.com', userId: 'admin', dataDir: dir })
  try {
    const verifier = 'a'.repeat(43)
    const query = new URLSearchParams({ client_id: 'orca-desktop', response_type: 'code', redirect_uri: 'http://127.0.0.1:1234/auth/callback', nonce: 'nonce', state: 'state', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', local_profile_id: 'local' })
    const login = await service.app.request(`/v1/desktop/auth/authorize?${query}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ secret: 'a'.repeat(32) }) })
    expect(login.status).toBe(303)
    const code = new URL(login.headers.get('location')!).searchParams.get('code')
    const post = (path: string, data: object, access?: string) => service.app.request(`/v1/desktop/auth/${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(access ? { authorization: `Bearer ${access}` } : {}) }, body: JSON.stringify(data) })
    const exchange = await post('session', { code, codeVerifier: verifier, nonce: 'nonce', state: 'state', redirectUri: 'http://127.0.0.1:1234/auth/callback', localProfileId: 'local' })
    expect(exchange.status).toBe(200)
    const session = await exchange.json() as { accessToken: string; refreshToken: string; cloud: { cloudProfileId: string } }
    const key = Buffer.alloc(32)
    const host = createHash('sha256').update(key).digest('base64url').slice(0, 16)
    const minted = await post('relay-token', { relayHostId: host, hostPublicKeyB64: key.toString('base64') }, session.accessToken)
    expect(minted.status).toBe(200)
    const { relayToken } = await minted.json() as { relayToken: string }
    const jwks = await (await service.app.request('/.well-known/jwks.json')).json() as { keys: [] }
    const verified = await jwtVerify(relayToken, createLocalJWKSet(jwks), { issuer: 'https://auth.example', audience: 'orca-relay', algorithms: ['ES256'] })
    expect(verified.payload).toMatchObject({ sub: 'admin', prof: session.cloud.cloudProfileId, relayHostId: 'Zmh6rfhivXdsj8GL', purpose: 'host-control' })
    const rotated = await post('refresh', { refreshToken: session.refreshToken })
    expect(rotated.status).toBe(200)
    const next = await rotated.json() as { refreshToken: string }
    expect((await post('refresh', { refreshToken: session.refreshToken })).status).toBe(401)
    expect((await post('refresh', { refreshToken: next.refreshToken })).status).toBe(401)
  } finally { service.close(); rmSync(dir, { recursive: true, force: true }) }
})
