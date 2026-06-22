ALTER TABLE products
  ADD COLUMN IF NOT EXISTS barcode TEXT NULL;

ALTER TABLE products
  ADD COLUMN IF NOT EXISTS description TEXT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS products_company_barcode_unique
  ON products (company_id, barcode)
  WHERE barcode IS NOT NULL;

