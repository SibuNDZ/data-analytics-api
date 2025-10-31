-- Migration to fix schema issues
-- Run this with: npx wrangler d1 execute DB_NAME --local --file=./migrations/fix-schema.sql

-- 1. Fix payments table
CREATE TABLE IF NOT EXISTS payments_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  provider TEXT NOT NULL,
  provider_order_id TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT DEFAULT 'usd',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP), -- CORRECTED
  updated_at TEXT DEFAULT (CURRENT_TIMESTAMP),         -- CORRECTED
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Copy existing data if any
INSERT INTO payments_new (id, user_id, client_id, provider, provider_order_id, plan, amount_cents, currency, status, created_at, updated_at)
SELECT id, user_id, client_id, provider, provider_order_id, plan, 
       amount_cents, currency, status, created_at, CURRENT_TIMESTAMP as updated_at
FROM payments;

-- Drop old table and rename new one
DROP TABLE payments;
ALTER TABLE payments_new RENAME TO payments;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_order_id ON payments(provider_order_id);

-- 2. Add missing columns to users table for password reset
ALTER TABLE users ADD COLUMN password_reset_token TEXT;
ALTER TABLE users ADD COLUMN password_reset_expires TEXT;

-- Verify the changes
SELECT 'Migration completed successfully' as status;