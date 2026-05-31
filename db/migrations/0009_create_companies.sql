CREATE TABLE companies (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  currency TEXT NOT NULL,
  timezone TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  CONSTRAINT companies_name_unique UNIQUE (name)
);

CREATE INDEX companies_created_at_idx ON companies (created_at);
