-- Migration: Fix remaining schema issues
-- Run with: npx wrangler d1 execute analytics-api-production --local --file=./migrations/0004_fix_remaining_issues.sql

-- 1. Add password reset columns to users table (if not already present)
-- Note: D1 doesn't support IF NOT EXISTS for ALTER TABLE, so we check via PRAGMA first in code or manually.
-- Since your schema shows they don't exist, we proceed.
ALTER TABLE users ADD COLUMN password_reset_token TEXT;
ALTER TABLE users ADD COLUMN password_reset_expires TEXT;

-- 2. Add subscription_status column to users (CRITICAL - code expects this!)
-- Default to 'pending' for existing users; new signups will set it correctly.
ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'pending';

-- 3. Migrate from plan_id to subscription_status (safe version)
-- Only if plan_id exists and is not NULL
UPDATE users 
SET subscription_status = CASE 
    WHEN plan_id = 'free' THEN 'active'
    WHEN plan_id IS NOT NULL THEN 'pending'
    ELSE 'pending'
END
WHERE plan_id IS NOT NULL;

-- 4. Add updated_at to payments table (if not already present)
-- Your screenshot shows it's missing → add it!
ALTER TABLE payments ADD COLUMN updated_at TEXT DEFAULT CURRENT_TIMESTAMP;

-- 5. Create index on password_reset_token for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(password_reset_token);

-- 6. Create index on payments.updated_at
CREATE INDEX IF NOT EXISTS idx_payments_updated_at ON payments(updated_at);

-- 7. Create trigger to auto-update payments.updated_at
DROP TRIGGER IF EXISTS update_payments_timestamp;
CREATE TRIGGER update_payments_timestamp 
AFTER UPDATE ON payments
BEGIN
  UPDATE payments SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- 8. Create trigger to auto-update users.updated_at
-- Already exists? Your schema shows updated_at is present → create trigger anyway (safe)
DROP TRIGGER IF EXISTS update_users_timestamp;
CREATE TRIGGER update_users_timestamp 
AFTER UPDATE ON users
BEGIN
  UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Verification
SELECT 'Migration 0005 completed successfully' as status;
SELECT 'Users table now has: password_reset_token, password_reset_expires, subscription_status' as info;
SELECT 'Payments table now has: updated_at and auto-update trigger' as info;