CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  email VARCHAR(320) NOT NULL,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  CONSTRAINT users_company_email_unique UNIQUE (company_id, email)
);

CREATE INDEX users_company_id_idx ON users (company_id);
