import { spawn } from 'node:child_process'
import { createHash, createHmac } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { buildHostProofMacInput, HOST_CHALLENGE_PLAINTEXT_DOMAIN } from '@orca-cloud/relay-contract/host-proof-transcript'
import nacl from 'tweetnacl'
import WebSocket from 'ws'

const count = Number(process.env.BENCH_PAIRS || 10)
const seconds = Number(process.env.BENCH_SECONDS || 5)
const tmp = mkdtempSync(join(tmpdir(), 'relay-bench-'))
const profileDir = process.env.BENCH_PROFILE_DIR
if (profileDir) mkdirSync(profileDir, { recursive: true })
const { publicKey, privateKey } = await generateKeyPair('ES256')
const jwk = await exportJWK(publicKey)
const jwks = createServer((_, res) => res.end(JSON.stringify({ keys: [{ ...jwk, kid: 'bench', alg: 'ES256', use: 'sig' }] })))
await new Promise(r => jwks.listen(0, '127.0.0.1', r))
const issuer = `http://127.0.0.1:${jwks.address().port}`
const reserve = createServer()
await new Promise(r => reserve.listen(0, '127.0.0.1', r))
const port = reserve.address().port
await new Promise(r => reserve.close(r))
const url = `http://127.0.0.1:${port}`
const args = [...(profileDir ? ['--cpu-prof', `--cpu-prof-dir=${profileDir}`] : []), '--import', 'tsx', '--conditions=orca-source', 'src/index.ts']
const relay = spawn(process.execPath, args, { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(port), ORCA_RELAY_PUBLIC_URL: url, ORCA_RELAY_CELL_URL: url, ORCA_RELAY_AUTH_ISSUER: issuer, ORCA_RELAY_JWKS_URL: `${issuer}/jwks`, ORCA_RELAY_ASSIGNMENT_SIGNING_KEY: 'test-assignment-key-with-at-least-32-bytes', ORCA_RELAY_DATA_DIR: tmp, ORCA_RELAY_ADMIN_AUDIENCE: `${url}/v1/admin/drain`, ORCA_RELAY_DEPLOY_SERVICE_ACCOUNT: 'deploy@example.com', ORCA_RELAY_MONITOR_SERVICE_ACCOUNT: 'monitor@example.com', ORCA_RELAY_FENCE_SERVICE_ACCOUNT: 'fence@example.com', ORCA_RELAY_IMAGE_DIGEST: `sha256:${'a'.repeat(64)}`, ORCA_RELAY_ADMIN_JWKS_URL: `${issuer}/jwks` }, stdio: ['ignore', 'pipe', 'pipe'] })
let errors = ''
relay.stderr.on('data', x => { errors += x })
const message = socket => new Promise((resolve, reject) => { const timer = setTimeout(() => { clean(); reject(Error('message timeout')) }, 10000); const clean = () => { clearTimeout(timer); socket.off('message', onMessage); socket.off('close', onClose); socket.off('error', onError) }; const onMessage = d => { clean(); resolve(JSON.parse(d.toString())) }; const onClose = (c, r) => { clean(); reject(Error(`closed ${c}: ${r}`)) }; const onError = e => { clean(); reject(e) }; socket.once('message', onMessage); socket.once('close', onClose); socket.once('error', onError) })
let source = 0
const open = async (path, headers = {}) => { const socket = new WebSocket(url.replace('http:', 'ws:') + path, { headers: { 'x-forwarded-for': `spoofed, 192.0.2.${++source}, 35.191.0.1`, ...headers }, perMessageDeflate: false }); await new Promise((r, j) => { socket.once('open', r); socket.once('error', j) }); return socket }
const percentile = (a, p) => [...a].sort((x,y)=>x-y)[Math.min(a.length-1, Math.floor(a.length*p))]
const pairs = []
try {
 await new Promise((resolve, reject) => { relay.stdout.on('data', d => { if (d.toString().includes('[orca-relay] listening')) resolve() }); relay.once('exit', c => reject(Error(`relay exited ${c}: ${errors}`))); setTimeout(() => reject(Error(`startup timeout: ${errors}`)), 15000).unref() })
 const start = performance.now(), latencies = []
 for (let i = 0; i < count; i++) {
  const t = performance.now(), keys = nacl.box.keyPair(), hostId = createHash('sha256').update(keys.publicKey).digest('base64url').slice(0,16)
  const token = await new SignJWT({ prof:'profile-1', org:'org-1', purpose:'host-control', relayHostId:hostId }).setProtectedHeader({ alg:'ES256', kid:'bench' }).setIssuer(issuer).setAudience('orca-relay').setSubject('user-1').setIssuedAt().setExpirationTime('5m').sign(privateKey)
  const host = await open('/v1/host/control', { authorization:`Bearer ${token}` })
  let next = message(host); host.send(JSON.stringify({ type:'host-hello', v:1, relayHostId:hostId, assignmentEpoch:1, hostPublicKeyB64:Buffer.from(keys.publicKey).toString('base64'), appVersion:'bench' }))
  const challenge = await next
  const plaintext = nacl.box.open(Buffer.from(challenge.ciphertextB64,'base64'), Buffer.from(challenge.nonceB64,'base64'), Buffer.from(challenge.relayEphemeralPublicKeyB64,'base64'), keys.secretKey)
  if (!plaintext) throw Error('challenge decrypt failed')
  const domain = Buffer.from(`${HOST_CHALLENGE_PLAINTEXT_DOMAIN}\0`), length = new DataView(plaintext.buffer, plaintext.byteOffset + domain.length, 4).getUint32(0, false), begin = domain.length + 4
  const proofB64 = createHmac('sha256', plaintext.subarray(begin+length)).update(buildHostProofMacInput(plaintext.subarray(begin,begin+length))).digest('base64')
  next = message(host); host.send(JSON.stringify({ type:'host-challenge-ack', challengeId:challenge.challengeId, proofB64 })); const ack = await next
  next = message(host); host.send(JSON.stringify({ type:'invite-create', reqId:`invite-${i}`, relayDeviceId:`device-${i}` })); const invite = await next
  const phone = await open(`/v1/connect/${hostId}`); next = message(host); phone.send(JSON.stringify({type:'relay-auth',v:1,mode:'connect',credential:invite.inviteToken})); const connection = await next
  const data = await open(`/v1/host/data/${connection.connId}`); next = message(phone); data.send(JSON.stringify({type:'host-data-auth',v:1,connTicket:connection.connTicket,generation:ack.generation})); const hello = await next; if (!hello.ok) throw Error(JSON.stringify(hello))
  pairs.push({host,phone,data}); latencies.push(performance.now()-t)
 }
 console.log(JSON.stringify({stage:'setup', pairs:count, seconds:(performance.now()-start)/1000, p50:percentile(latencies,.5), p95:percentile(latencies,.95), p99:percentile(latencies,.99), relayPid:relay.pid}))
 for (const size of [64,1024,16384]) {
  const times = [], started = performance.now(), end = started + seconds*1000; let messages = 0
  await Promise.all(pairs.map(async ({phone,data}) => { const payload = Buffer.alloc(size, 42); while (performance.now() < end) { const t = performance.now(); await new Promise((r,j) => { const done = value => { data.off('error', j); r(value) }; data.once('message', done); data.once('error',j); phone.send(payload) }); times.push(performance.now()-t); messages++ } }))
  const elapsed = (performance.now()-started)/1000
  console.log(JSON.stringify({stage:'splice', size, pairs:count, messages, seconds:elapsed, messagesPerSecond:messages/elapsed, p50:percentile(times,.5), p95:percentile(times,.95), p99:percentile(times,.99)}))
 }
} finally {
 for (const pair of pairs) for (const socket of Object.values(pair)) socket.terminate()
 relay.kill('SIGTERM'); await new Promise(r => relay.once('exit',r)); await new Promise(r => jwks.close(r)); rmSync(tmp,{recursive:true,force:true})
}
