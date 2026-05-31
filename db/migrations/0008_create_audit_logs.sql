ALTER TABLE audit_logs
  RENAME TO auth_audit_logs;

CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  details TEXT NULL,
  timestamp BIGINT NOT NULL,
  CONSTRAINT audit_logs_user_fk FOREIGN KEY (company_id, user_id) REFERENCES users (company_id, id)
);

CREATE INDEX audit_logs_company_id_idx ON audit_logs (company_id);
CREATE INDEX audit_logs_company_user_id_idx ON audit_logs (company_id, user_id);
CREATE INDEX audit_logs_company_resource_idx ON audit_logs (company_id, resource);
CREATE INDEX audit_logs_company_timestamp_idx ON audit_logs (company_id, timestamp);
