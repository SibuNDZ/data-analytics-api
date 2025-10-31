#!/bin/bash

echo "=== Migrating Staging Database ==="
wrangler d1 execute analytics-api-staging --env staging --command "
ALTER TABLE analysis_jobs ADD COLUMN source_id INTEGER;
ALTER TABLE analysis_jobs ADD COLUMN error TEXT;
ALTER TABLE analysis_jobs ADD COLUMN started_at TEXT;
CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_client ON analysis_jobs(client_id);
"

echo ""
echo "=== Migrating Production Database ==="
wrangler d1 execute analytics-api-production --env production --command "
ALTER TABLE analysis_jobs ADD COLUMN source_id INTEGER;
ALTER TABLE analysis_jobs ADD COLUMN error TEXT;
ALTER TABLE analysis_jobs ADD COLUMN started_at TEXT;
CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_client ON analysis_jobs(client_id);
"

echo ""
echo "✅ Migration complete!"
