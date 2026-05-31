CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  branch_id BIGINT NULL,
  user_id BIGINT NULL,
  event_type TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  metadata_json TEXT NULL,
  CONSTRAINT audit_logs_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX audit_logs_company_id_idx ON audit_logs (company_id);
CREATE INDEX audit_logs_company_created_at_idx ON audit_logs (company_id, created_at);
CREATE INDEX audit_logs_user_id_idx ON audit_logs (user_id);
