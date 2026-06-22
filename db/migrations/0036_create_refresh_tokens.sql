CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER NULL,
  CONSTRAINT rt_company_token_unique UNIQUE (company_id, token_hash),
  CONSTRAINT rt_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS rt_company_id_idx ON refresh_tokens (company_id);
CREATE INDEX IF NOT EXISTS rt_user_id_idx ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS rt_token_hash_idx ON refresh_tokens (token_hash);
