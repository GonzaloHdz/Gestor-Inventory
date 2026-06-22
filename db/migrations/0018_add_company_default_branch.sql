ALTER TABLE branches
  ADD CONSTRAINT branches_id_unique UNIQUE (id);

ALTER TABLE companies
  ADD COLUMN default_branch_id BIGINT NULL;

ALTER TABLE companies
  ADD CONSTRAINT companies_default_branch_fk FOREIGN KEY (default_branch_id) REFERENCES branches (id) ON DELETE SET NULL;
