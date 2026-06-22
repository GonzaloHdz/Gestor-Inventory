ALTER TABLE branches
  ADD COLUMN IF NOT EXISTS address TEXT NULL;

ALTER TABLE branches
  ADD COLUMN IF NOT EXISTS city TEXT NULL;

ALTER TABLE branches
  ADD COLUMN IF NOT EXISTS country TEXT NULL;

ALTER TABLE branches
  ADD CONSTRAINT branches_company_fk FOREIGN KEY (company_id) REFERENCES companies (id);

CREATE INDEX IF NOT EXISTS idx_branches_company_id ON branches(company_id);
CREATE INDEX IF NOT EXISTS idx_branches_name ON branches(name);
