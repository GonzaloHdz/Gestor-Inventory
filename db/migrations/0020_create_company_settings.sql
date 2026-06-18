CREATE TABLE company_settings (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  setting_key TEXT NOT NULL,
  setting_value TEXT NOT NULL,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
  updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
  CONSTRAINT company_settings_company_fk FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
  CONSTRAINT company_settings_company_key_unique UNIQUE (company_id, setting_key)
);

CREATE INDEX company_settings_company_id_idx ON company_settings (company_id);
