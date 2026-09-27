import {
  index,
  pgTable,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core'
import { users } from './users.ts'

export const oauthStates = pgTable(
  'oauth_states',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    state: text('state').notNull(),

    provider: text('provider').notNull(),

    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),

    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),

    userId: uuid('user_id').references(() => users.id, {
      onDelete: 'cascade',
    }),
  },
  (table) => [
    index('oauth_states_state_idx').on(table.state),
    index('oauth_states_expires_at_idx').on(table.expiresAt),
  ],
)