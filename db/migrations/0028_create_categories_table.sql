ALTER TABLE categories
  ADD COLUMN IF NOT EXISTS description TEXT NULL;

ALTER TABLE categories
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

UPDATE categories
SET status = CASE WHEN is_active THEN 'active' ELSE 'inactive' END
WHERE status IS NULL;

ALTER TABLE categories
  ADD CONSTRAINT categories_company_fk FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_categories_company_id ON categories (company_id);
