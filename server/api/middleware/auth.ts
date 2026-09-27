import type { Context, Next } from 'hono'

import { createDb } from '../../db/client.ts'
import { authenticateSession } from '../services/authService.ts'

export type AuthVariables = {
  userId: string
  sessionId: string
}

let db: ReturnType<typeof createDb> | undefined

function getDb() {
  if (!db) {
    const databaseUrl = process.env.DATABASE_URL

    if (!databaseUrl) {
      throw new Error('DATABASE_URL is required for session authentication')
    }

    db = createDb(databaseUrl)
  }

  return db
}

export async function authMiddleware(c: Context, next: Next) {
  const sessionHeader = c.req.header('ADAMANT_SESSION')
  const sessionQuery = c.req.query('session')

  const token = sessionHeader ?? sessionQuery

  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  try {
    const database = getDb()
    const session = await authenticateSession(database, token)

    if (!session) {
      return c.json({ error: 'Unauthorized' }, 401)
    }

    c.set('userId', session.userId)
    c.set('sessionId', session.sessionId)

    await next()
  } catch (error) {
    console.error(
      error instanceof Error
        ? error.message
        : 'Failed to authenticate session',
    )

    return c.json({ error: 'Server misconfiguration' }, 500)
  }
}