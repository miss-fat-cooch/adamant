import { Hono } from 'hono'

const activity = new Hono()

activity.get('/', async (c) => {
  // Stub for SSE events used by `adamant watch`
  // In a real implementation, this would use hono/streaming
  return c.json({ message: 'SSE stream connected (stub)' })
})

export { activity }
