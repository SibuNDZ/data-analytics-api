-- Enhanced User Management with consistent schema
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt_hex TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    company TEXT,
    subscription_status TEXT DEFAULT 'free',
    email_verified INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Enhanced API Keys with Advanced Features
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT UNIQUE NOT NULL,
    key_hash TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT 'Default Key',
    permissions TEXT DEFAULT 'read',
    rate_limit INTEGER DEFAULT 1000,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    usage_count INTEGER DEFAULT 0,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Data Management Tables
CREATE TABLE IF NOT EXISTS data_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    row_count INTEGER DEFAULT 0,
    last_ingested DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS raw_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    data_row TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_id) REFERENCES data_sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    parameters TEXT,
    results TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ml_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    model_name TEXT NOT NULL,
    model_type TEXT NOT NULL,
    version TEXT DEFAULT '1.0',
    is_active BOOLEAN DEFAULT true,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Comprehensive Usage Tracking
CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT,
    request_size INTEGER,
    response_size INTEGER,
    FOREIGN KEY (key_id) REFERENCES api_keys(key_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Subscription Plans
CREATE TABLE IF NOT EXISTS subscription_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stripe_price_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL,
    currency TEXT DEFAULT 'usd',
    billing_period TEXT NOT NULL,
    rate_limit INTEGER DEFAULT 1000,
    features TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Billing History
CREATE TABLE IF NOT EXISTS billing_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    stripe_invoice_id TEXT,
    amount_cents INTEGER NOT NULL,
    currency TEXT DEFAULT 'usd',
    status TEXT NOT NULL,
    period_start DATE,
    period_end DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Rate Limiting Tracking
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    window_start DATETIME NOT NULL,
    request_count INTEGER DEFAULT 0,
    FOREIGN KEY (key_id) REFERENCES api_keys(key_id)
);

-- Indexes for Performance
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_id ON api_keys(key_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_usage_key_id ON api_usage(key_id);
CREATE INDEX IF NOT EXISTS idx_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON api_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_client_id ON users(client_id);
CREATE INDEX IF NOT EXISTS idx_data_sources_client_id ON data_sources(client_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_client_id ON analysis_jobs(client_id);
CREATE INDEX IF NOT EXISTS idx_ml_models_client_id ON ml_models(client_id);

-- Insert default subscription plans
INSERT OR IGNORE INTO subscription_plans (stripe_price_id, name, description, price_cents, billing_period, rate_limit, features) VALUES
('price_free', 'Free Plan', 'Basic API access', 0, 'month', 1000, '["Basic Analytics", "1000 requests/hour"]'),
('price_pro', 'Pro Plan', 'Professional features', 2900, 'month', 10000, '["Advanced Analytics", "10000 requests/hour", "Priority Support"]'),
('price_enterprise', 'Enterprise Plan', 'Full featured access', 9900, 'month', 100000, '["All Features", "100000 requests/hour", "24/7 Support", "Custom Integration"]');