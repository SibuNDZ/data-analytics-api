PRAGMA defer_foreign_keys=TRUE;
CREATE TABLE d1_migrations(
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT UNIQUE,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);
INSERT INTO d1_migrations VALUES(1,'0001_create_comments_table.sql','2025-08-26 20:21:37');
INSERT INTO d1_migrations VALUES(2,'0002_add_data_science_tables.sql','2025-08-26 20:59:55');
INSERT INTO d1_migrations VALUES(3,'0000_initial_schema.sql','2025-09-13 16:57:35');
CREATE TABLE comments (
    id INTEGER PRIMARY KEY NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL
);
INSERT INTO comments VALUES(1,'Kristian','Congrats!');
INSERT INTO comments VALUES(2,'Serena','Great job!');
INSERT INTO comments VALUES(3,'Max','Keep up the good work!');
CREATE TABLE clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  api_key TEXT UNIQUE NOT NULL,
  plan TEXT DEFAULT 'free',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE subscription_plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  price_cents INTEGER NOT NULL,
  currency TEXT DEFAULT 'usd',
  billing_period TEXT NOT NULL,
  api_calls_limit INTEGER DEFAULT 1000,
  rate_limit_per_hour INTEGER DEFAULT 100,
  features TEXT,
  is_active BOOLEAN DEFAULT true,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO subscription_plans VALUES(1,'free','Free Plan','Perfect for getting started',0,'usd','month',1000,100,'["1,000 API calls/month", "Basic analytics", "1 data source", "Email support", "7-day data retention"]',1,'2025-10-15 22:24:42');
INSERT INTO subscription_plans VALUES(2,'basic','Basic Plan','Essential features for small teams',1500,'usd','month',1000,200,'["1,000 API calls/month", "Basic analytics", "1 data source", "Email support", "7-day data retention"]',1,'2025-10-15 22:24:42');
INSERT INTO subscription_plans VALUES(3,'pro','Pro Plan','Advanced features for growing businesses',4900,'usd','month',10000,1000,'["10,000 API calls/month", "Advanced analytics", "5 data sources", "Priority email support", "30-day data retention", "Custom reports"]',1,'2025-10-15 22:24:42');
INSERT INTO subscription_plans VALUES(4,'premium','Premium Plan','Complete solution for enterprises',9900,'usd','month',-1,-1,'["Unlimited API calls", "AI-powered analytics", "Unlimited data sources", "24/7 priority support", "90-day data retention", "Custom reports & dashboards", "Dedicated account manager"]',1,'2025-10-15 22:24:42');
INSERT INTO subscription_plans VALUES(5,'enterprise','Enterprise Plan','Custom solution for large organizations',0,'usd','custom',-1,-1,'["Custom API limits", "White-label solution", "Custom integrations", "On-premise deployment", "SLA guarantee", "Dedicated support team", "Custom contracts"]',1,'2025-10-15 22:24:42');
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt_hex TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  company TEXT,
  plan_id TEXT DEFAULT 'free', 
  email_verified INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login_at DATETIME,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
  FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id) 
);
CREATE TABLE api_keys (
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
  expires_at DATETIME, key_salt_hex TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE data_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  source_name TEXT NOT NULL,
  source_type TEXT NOT NULL,
  row_count INTEGER DEFAULT 0,
  last_ingested DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
CREATE TABLE raw_data (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL,
  data_row TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (source_id) REFERENCES data_sources(id) ON DELETE CASCADE
);
CREATE TABLE analysis_jobs (
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
CREATE TABLE ml_models (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  model_name TEXT NOT NULL,
  model_type TEXT NOT NULL,
  version TEXT DEFAULT '1.0',
  is_active BOOLEAN DEFAULT true,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
CREATE TABLE api_usage (
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
CREATE TABLE billing_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  payment_provider TEXT,
  provider_invoice_id TEXT,
  amount_cents INTEGER NOT NULL,
  currency TEXT DEFAULT 'usd',
  status TEXT NOT NULL,
  plan TEXT NOT NULL,
  period_start DATE,
  period_end DATE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  provider TEXT NOT NULL,
  provider_order_id TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT DEFAULT 'usd',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
CREATE TABLE rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id TEXT NOT NULL,
  window_start DATETIME NOT NULL,
  request_count INTEGER DEFAULT 0,
  FOREIGN KEY (key_id) REFERENCES api_keys(key_id)
);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('d1_migrations',3);
INSERT INTO sqlite_sequence VALUES('subscription_plans',5);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_id ON api_keys(key_id);
CREATE INDEX idx_api_keys_active ON api_keys(is_active);
CREATE INDEX idx_usage_key_id ON api_usage(key_id);
CREATE INDEX idx_usage_user_id ON api_usage(user_id);
CREATE INDEX idx_usage_timestamp ON api_usage(timestamp);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_client_id ON users(client_id);
CREATE INDEX idx_data_sources_client_id ON data_sources(client_id);
CREATE INDEX idx_analysis_jobs_client_id ON analysis_jobs(client_id);
CREATE INDEX idx_ml_models_client_id ON ml_models(client_id);
CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_payments_order_id ON payments(provider_order_id);
CREATE INDEX idx_billing_history_user_id ON billing_history(user_id);