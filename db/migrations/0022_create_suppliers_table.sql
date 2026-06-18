CREATE TABLE suppliers (
  company_id BIGINT NOT NULL,
  id BIGSERIAL NOT NULL,
  name TEXT NOT NULL,
  document_id TEXT NULL,
  contact_email TEXT NULL,
  phone TEXT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
  updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
  CONSTRAINT suppliers_pk PRIMARY KEY (company_id, id),
  CONSTRAINT suppliers_company_fk FOREIGN KEY (company_id) REFERENCES companies (id),
  CONSTRAINT suppliers_company_document_id_unique UNIQUE (company_id, document_id)
);

CREATE INDEX idx_suppliers_company_id ON suppliers (company_id);
