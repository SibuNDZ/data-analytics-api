#!/bin/bash

echo "=== Migrating REMOTE Staging Database ==="
wrangler d1 execute analytics-api-staging --env staging --remote --command "ALTER TABLE analysis_jobs ADD COLUMN source_id INTEGER;" 2>/dev/null || echo "✓ source_id exists"
wrangler d1 execute analytics-api-staging --env staging --remote --command "ALTER TABLE analysis_jobs ADD COLUMN error TEXT;" 2>/dev/null || echo "✓ error exists"
wrangler d1 execute analytics-api-staging --env staging --remote --command "ALTER TABLE analysis_jobs ADD COLUMN started_at TEXT;" 2>/dev/null || echo "✓ started_at exists"
wrangler d1 execute analytics-api-staging --env staging --remote --command "CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);"
wrangler d1 execute analytics-api-staging --env staging --remote --command "CREATE INDEX IF NOT EXISTS idx_jobs_client ON analysis_jobs(client_id);"

echo ""
echo "=== Migrating REMOTE Production Database ==="
wrangler d1 execute analytics-api-production --env production --remote --command "ALTER TABLE analysis_jobs ADD COLUMN source_id INTEGER;" 2>/dev/null || echo "✓ source_id exists"
wrangler d1 execute analytics-api-production --env production --remote --command "ALTER TABLE analysis_jobs ADD COLUMN error TEXT;" 2>/dev/null || echo "✓ error exists"
wrangler d1 execute analytics-api-production --env production --remote --command "ALTER TABLE analysis_jobs ADD COLUMN started_at TEXT;" 2>/dev/null || echo "✓ started_at exists"
wrangler d1 execute analytics-api-production --env production --remote --command "CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);"
wrangler d1 execute analytics-api-production --env production --remote --command "CREATE INDEX IF NOT EXISTS idx_jobs_client ON analysis_jobs(client_id);"

echo ""
echo "✅ Remote migration complete!"
