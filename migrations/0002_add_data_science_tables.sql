-- Migration number: 0002 	 2025-08-26T20:52:55.916Z
-- Client and project management
CREATE TABLE clients (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  api_key TEXT UNIQUE NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Data sources and ingestion tracking
CREATE TABLE data_sources (
  id INTEGER PRIMARY KEY IDENTITY(1,1),
  client_id INTEGER,
  FOREIGN KEY (client_id) REFERENCES clients(id),
  source_name TEXT NOT NULL,
  source_type TEXT NOT NULL, -- 'file', 'api', 'database'
  schema_definition TEXT, -- JSON as TEXT for D1 compatibility
  last_ingested DATETIME,
  row_count INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Analysis job queue and results
CREATE TABLE analysis_jobs (
  id INTEGER PRIMARY KEY IDENTITY(1,1),
  client_id INTEGER REFERENCES clients(id),
  job_type TEXT NOT NULL, -- 'descriptive', 'predictive', 'report'
  status TEXT DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
  parameters TEXT, -- JSON as TEXT for D1 compatibility
  results TEXT, -- JSON as TEXT for D1 compatibility
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME
);

-- ML model registry
CREATE TABLE ml_models (
  id INTEGER PRIMARY KEY IDENTITY(1,1),
  client_id INTEGER REFERENCES clients(id),
  model_name TEXT NOT NULL,
  model_type TEXT NOT NULL, -- 'regression', 'classification', 'clustering'
  training_data_hash TEXT,
  accuracy_metrics TEXT, -- JSON as TEXT for D1 compatibility
  version INTEGER DEFAULT 1,
  is_active BOOLEAN DEFAULT true,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Raw data storage (for smaller datasets)
CREATE TABLE raw_data (
  id INTEGER PRIMARY KEY IDENTITY(1,1),
  source_id INTEGER REFERENCES data_sources(id),
  data_row TEXT, -- JSON as TEXT for D1 compatibility
  ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data for testing
INSERT INTO clients (name, api_key) VALUES 
  ('Demo Client', 'demo_key_12345'),
  ('Test Corp', 'test_key_67890');

INSERT INTO data_sources (client_id, source_name, source_type, row_count) VALUES 
  (1, 'Sales Data Q3', 'file', 1500),
  (1, 'Customer Analytics', 'api', 2300),
  (2, 'Financial Reports', 'database', 890);