ALTER TABLE products
  ADD COLUMN IF NOT EXISTS stock_minimum BIGINT NOT NULL DEFAULT 0;

ALTER TABLE products
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

ALTER TABLE products
  ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT);

ALTER TABLE products
  ADD COLUMN IF NOT EXISTS updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT);

ALTER TABLE products
  ALTER COLUMN category_id SET NOT NULL;

DO $$
BEGIN
  ALTER TABLE products
    ADD CONSTRAINT products_company_sku_unique UNIQUE (company_id, sku);
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER TABLE products
    ADD CONSTRAINT products_category_fk FOREIGN KEY (company_id, category_id) REFERENCES categories (company_id, id);
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS products_company_sku_idx ON products (company_id, sku);
