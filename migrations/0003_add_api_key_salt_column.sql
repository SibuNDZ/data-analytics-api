-- File: migrations/0003_add_api_key_salt_column.sql
ALTER TABLE api_keys ADD COLUMN key_salt_hex TEXT;