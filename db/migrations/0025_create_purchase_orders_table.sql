CREATE TABLE purchase_orders (
  company_id BIGINT NOT NULL,
  id BIGSERIAL NOT NULL,
  supplier_id BIGINT NOT NULL,
  status TEXT NOT NULL DEFAULT 'created',
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
  updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
  CONSTRAINT purchase_orders_pk PRIMARY KEY (company_id, id),
  CONSTRAINT purchase_orders_supplier_fk FOREIGN KEY (company_id, supplier_id) REFERENCES suppliers (company_id, id)
);

CREATE INDEX purchase_orders_company_id_idx ON purchase_orders (company_id);
CREATE INDEX purchase_orders_supplier_id_idx ON purchase_orders (company_id, supplier_id);
