CREATE TABLE password_reset_tokens (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  CONSTRAINT prt_company_token_unique UNIQUE (company_id, token_hash),
  CONSTRAINT prt_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX prt_company_id_idx ON password_reset_tokens (company_id);
CREATE INDEX prt_user_id_idx ON password_reset_tokens (user_id);
CREATE INDEX prt_token_hash_idx ON password_reset_tokens (token_hash);
