CREATE TABLE email_verification_tokens (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  CONSTRAINT evt_company_token_unique UNIQUE (company_id, token_hash),
  CONSTRAINT evt_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX evt_company_id_idx ON email_verification_tokens (company_id);
CREATE INDEX evt_user_id_idx ON email_verification_tokens (user_id);
CREATE INDEX evt_token_hash_idx ON email_verification_tokens (token_hash);
