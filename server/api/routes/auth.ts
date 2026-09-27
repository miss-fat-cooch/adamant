import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { Hono } from 'hono'

import { createDb } from '../../db/client.ts'
import {
  authenticateSession,
  consumeOAuthState,
  createOAuthState,
  createSession,
  getUserAuthInfo,
  revokeSession,
  upsertOAuthIdentity,
  type OAuthProvider,
} from '../services/authService.ts'

// .env file ko automatically locate karke process.env me load karne ka logic
function ensureEnvLoaded() {
  const searchDirs = [
    process.cwd(),
    resolve(process.cwd(), '..'),
    resolve(process.cwd(), '../..'),
    'C:/Users/shrey/adamant',
  ]

  for (const dir of searchDirs) {
    const envFile = resolve(dir, '.env')
    if (existsSync(envFile)) {
      try {
        const raw = readFileSync(envFile, 'utf8')
        for (const line of raw.split(/\r?\n/)) {
          const trimmed = line.trim()
          if (!trimmed || trimmed.startsWith('#')) continue
          const eq = trimmed.indexOf('=')
          if (eq !== -1) {
            const key = trimmed.slice(0, eq).trim()
            let val = trimmed.slice(eq + 1).trim()
            if (
              (val.startsWith('"') && val.endsWith('"')) ||
              (val.startsWith("'") && val.endsWith("'"))
            ) {
              val = val.slice(1, -1)
            }
            process.env[key] = val
          }
        }
        break
      } catch (e) {
        console.error('Failed to parse .env file:', e)
      }
    }
  }
}

ensureEnvLoaded()

const auth = new Hono()

let db: ReturnType<typeof createDb> | undefined

function getDb() {
  if (!db) {
    ensureEnvLoaded()

    const databaseUrl =
      process.env.DATABASE_URL ||
      process.env.POSTGRES_URL ||
      process.env.DB_URL ||
      'postgresql://adamant:adamant@127.0.0.1:5432/adamant'

    if (!databaseUrl) {
      throw new Error('DATABASE_URL is required for authentication')
    }

    db = createDb(databaseUrl)
  }

  return db
}

function getRequiredEnv(name: string): string {
  ensureEnvLoaded()
  const value = process.env[name]

  if (!value) {
    throw new Error(`${name} is required for OAuth`)
  }

  return value
}

function getOAuthRedirectUri(provider: OAuthProvider): string {
  return provider === 'github'
    ? getRequiredEnv('GITHUB_OAUTH_REDIRECT_URI')
    : getRequiredEnv('GOOGLE_OAUTH_REDIRECT_URI')
}

function getOAuthClientId(provider: OAuthProvider): string {
  return provider === 'github'
    ? getRequiredEnv('GITHUB_OAUTH_CLIENT_ID')
    : getRequiredEnv('GOOGLE_OAUTH_CLIENT_ID')
}

function getOAuthClientSecret(provider: OAuthProvider): string {
  return provider === 'github'
    ? getRequiredEnv('GITHUB_OAUTH_CLIENT_SECRET')
    : getRequiredEnv('GOOGLE_OAUTH_CLIENT_SECRET')
}

async function createOAuthAuthorizationUrl(
  provider: OAuthProvider,
): Promise<string> {
  const database = getDb()
  const state = await createOAuthState(database, provider)

  const redirectUri = getOAuthRedirectUri(provider)
  const clientId = getOAuthClientId(provider)

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
  })

  if (provider === 'github') {
    params.set('scope', 'read:user user:email')

    return `https://github.com/login/oauth/authorize?${params.toString()}`
  }

  params.set('response_type', 'code')
  params.set('scope', 'openid email profile')
  params.set('access_type', 'offline')

  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`
}

async function exchangeCode(
  provider: OAuthProvider,
  code: string,
): Promise<string> {
  const clientId = getOAuthClientId(provider)
  const clientSecret = getOAuthClientSecret(provider)
  const redirectUri = getOAuthRedirectUri(provider)

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
  })

  if (provider === 'github') {
    const response = await fetch(
      'https://github.com/login/oauth/access_token',
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
        },
        body,
      },
    )

    if (!response.ok) {
      throw new Error('GitHub OAuth token exchange failed')
    }

    const data = (await response.json()) as {
      access_token?: string
      error?: string
      error_description?: string
    }

    if (!data.access_token) {
      console.error('GitHub Token Response:', data)
      throw new Error(
        data.error_description ||
          data.error ||
          'GitHub OAuth token was not returned',
      )
    }

    return data.access_token
  }

  body.set('grant_type', 'authorization_code')

  const response = await fetch(
    'https://oauth2.googleapis.com/token',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    },
  )

  if (!response.ok) {
    throw new Error('Google OAuth token exchange failed')
  }

  const data = (await response.json()) as {
    access_token?: string
    error?: string
    error_description?: string
  }

  if (!data.access_token) {
    throw new Error(
      data.error_description ||
        data.error ||
        'Google OAuth token was not returned',
    )
  }

  return data.access_token
}

async function authenticateOAuthUser(
  provider: OAuthProvider,
  accessToken: string,
): Promise<{
  providerUserId: string
  username: string
  email?: string
}> {
  if (provider === 'github') {
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': 'Adamant',
      },
    })

    if (!userResponse.ok) {
      throw new Error('Failed to fetch GitHub user')
    }

    const user = (await userResponse.json()) as {
      id?: number
      login?: string
    }

    if (!user.id || !user.login) {
      throw new Error('GitHub user information is incomplete')
    }

    let verifiedEmail: string | undefined

    const emailsResponse = await fetch(
      'https://api.github.com/user/emails',
      {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'Adamant',
        },
      },
    )

    if (emailsResponse.ok) {
      const emails = (await emailsResponse.json()) as Array<{
        email?: string
        verified?: boolean
        primary?: boolean
      }>

      const primaryVerifiedEmail = emails.find(
        (entry) =>
          entry.email &&
          entry.verified &&
          entry.primary,
      )

      const verifiedEmailEntry =
        primaryVerifiedEmail ??
        emails.find(
          (entry) =>
            entry.email &&
            entry.verified,
        )

      verifiedEmail = verifiedEmailEntry?.email
    }

    return {
      providerUserId: String(user.id),
      username: user.login,
      ...(verifiedEmail ? { email: verifiedEmail } : {}),
    }
  }

  const response = await fetch(
    'https://openidconnect.googleapis.com/v1/userinfo',
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  )

  if (!response.ok) {
    throw new Error('Failed to fetch Google user')
  }

  const user = (await response.json()) as {
    sub?: string
    email?: string
    email_verified?: boolean
    name?: string
  }

  if (!user.sub) {
    throw new Error('Google user information is incomplete')
  }

  return {
    providerUserId: user.sub,
    username:
      user.name ??
      user.email ??
      `google_${user.sub}`,
    ...(user.email_verified && user.email
      ? { email: user.email }
      : {}),
  }
}

async function handleOAuthCallback(
  provider: OAuthProvider,
  code: string,
  state: string,
) {
  const database = getDb()

  const validState = await consumeOAuthState(
    database,
    provider,
    state,
  )

  if (!validState) {
    return Response.json(
      { error: 'Invalid or expired OAuth state' },
      { status: 400 },
    )
  }

  const accessToken = await exchangeCode(
    provider,
    code,
  )

  const identity = await authenticateOAuthUser(
    provider,
    accessToken,
  )

  const { userId } = await upsertOAuthIdentity(
    database,
    {
      provider,
      providerUserId: identity.providerUserId,
      username: identity.username,
      ...(identity.email
        ? { email: identity.email }
        : {}),
    },
  )

  const session = await createSession(
    database,
    userId,
  )

  return Response.json({
    token: session.token,
  })
}

auth.get('/github', async (c) => {
  try {
    const url =
      await createOAuthAuthorizationUrl('github')

    return c.redirect(url)
  } catch (error) {
    console.error('GitHub OAuth error:', error)

    const cause = (error as any)?.cause

    return c.json(
      {
        error: 'GitHub OAuth error',
        details: error instanceof Error ? error.message : String(error),
        cause: cause?.message || cause?.detail || String(cause || ''),
      },
      500,
    )
  }
})

auth.get('/github/callback', async (c) => {
  const code = c.req.query('code')
  const state = c.req.query('state')

  if (!code || !state) {
    return c.json(
      {
        error:
          'OAuth code and state are required',
      },
      400,
    )
  }

  try {
    return await handleOAuthCallback(
      'github',
      code,
      state,
    )
  } catch (error) {
    console.error('GitHub OAuth callback failed:', error)

    return c.json(
      {
        error: 'GitHub authentication failed',
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    )
  }
})

auth.get('/google', async (c) => {
  try {
    const url =
      await createOAuthAuthorizationUrl('google')

    return c.redirect(url)
  } catch (error) {
    console.error('Google OAuth error:', error)

    const cause = (error as any)?.cause

    return c.json(
      {
        error: 'Google OAuth error',
        details: error instanceof Error ? error.message : String(error),
        cause: cause?.message || cause?.detail || String(cause || ''),
      },
      500,
    )
  }
})

auth.get('/google/callback', async (c) => {
  const code = c.req.query('code')
  const state = c.req.query('state')

  if (!code || !state) {
    return c.json(
      {
        error:
          'OAuth code and state are required',
      },
      400,
    )
  }

  try {
    return await handleOAuthCallback(
      'google',
      code,
      state,
    )
  } catch (error) {
    console.error('Google OAuth callback failed:', error)

    return c.json(
      {
        error: 'Google authentication failed',
        details: error instanceof Error ? error.message : String(error),
      },
      500,
    )
  }
})

auth.post('/logout', async (c) => {
  const token =
    c.req.query('session') ||
    c.req.header('ADAMANT_SESSION') ||
    c.req.header('adamant_session') ||
    c.req.header('authorization')?.replace(/^Bearer\s+/i, '')

  if (!token) {
    return c.json(
      { error: 'Unauthorized', reason: 'No session token provided' },
      401,
    )
  }

  try {
    const database = getDb()

    const session = await authenticateSession(
      database,
      token,
    )

    if (!session) {
      return c.json(
        { error: 'Unauthorized', reason: 'Session not found or already revoked' },
        401,
      )
    }

    await revokeSession(
      database,
      session.sessionId,
    )

    return c.json({
      message: 'Logged out successfully',
    })
  } catch (error) {
    console.error('Failed to logout:', error)

    return c.json(
      { error: 'Failed to logout' },
      500,
    )
  }
})

auth.get('/me', async (c) => {
  const token =
    c.req.query('session') ||
    c.req.header('ADAMANT_SESSION') ||
    c.req.header('adamant_session') ||
    c.req.header('authorization')?.replace(/^Bearer\s+/i, '')

  if (!token) {
    return c.json(
      {
        error: 'Unauthorized',
        reason: 'Token was not found in header or ?session= query',
      },
      401,
    )
  }

  try {
    const database = getDb()

    const session = await authenticateSession(
      database,
      token,
    )

    if (!session) {
      return c.json(
        {
          error: 'Unauthorized',
          reason: 'Session token not found or expired in DB',
        },
        401,
      )
    }

    const user = await getUserAuthInfo(
      database,
      session.userId,
    )

    if (!user) {
      return c.json(
        { error: 'User not found' },
        404,
      )
    }

    return c.json({ user })
  } catch (error) {
    console.error('Failed to load user:', error)

    return c.json(
      { error: 'Failed to load user', details: String(error) },
      500,
    )
  }
})

export { auth }