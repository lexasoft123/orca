import { readFileSync } from 'node:fs'
import { serve } from '@hono/node-server'
import { z } from 'zod'
import { createService } from './service.js'

process.umask(0o077)

const env = z.object({
  PORT: z.coerce.number().int().positive().max(65535).default(8080),
  ORCA_AUTH_ISSUER: z.string().url(),
  ORCA_AUTH_CLIENT_ID: z.string().min(1).default('orca-desktop'),
  ORCA_AUTH_ADMIN_SECRET: z.string().min(32),
  ORCA_AUTH_EMAIL: z.email(),
  ORCA_AUTH_USER_ID: z.string().min(1).default('admin'),
  ORCA_AUTH_DATA_DIR: z.string().default('./data/relay-auth'),
  ORCA_AUTH_SIGNING_KEY_FILE: z.string().optional(),
  ORCA_AUTH_PREVIOUS_PUBLIC_KEY_FILE: z.string().optional()
}).parse(process.env)
const issuer = new URL(env.ORCA_AUTH_ISSUER)
if (issuer.origin !== env.ORCA_AUTH_ISSUER || (issuer.protocol !== 'https:' && !(issuer.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(issuer.hostname)))) throw new Error('ORCA_AUTH_ISSUER must be an HTTPS origin or loopback HTTP origin')
const service = await createService({ issuer: env.ORCA_AUTH_ISSUER, clientId: env.ORCA_AUTH_CLIENT_ID, secret: env.ORCA_AUTH_ADMIN_SECRET, email: env.ORCA_AUTH_EMAIL, userId: env.ORCA_AUTH_USER_ID, dataDir: env.ORCA_AUTH_DATA_DIR, signingKey: env.ORCA_AUTH_SIGNING_KEY_FILE ? readFileSync(env.ORCA_AUTH_SIGNING_KEY_FILE, 'utf8') : undefined, previousPublicKey: env.ORCA_AUTH_PREVIOUS_PUBLIC_KEY_FILE ? readFileSync(env.ORCA_AUTH_PREVIOUS_PUBLIC_KEY_FILE, 'utf8') : undefined })
serve({ fetch: service.app.fetch, port: env.PORT })
