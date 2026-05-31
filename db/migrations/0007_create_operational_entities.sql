ALTER TABLE users
  ADD CONSTRAINT users_company_id_id_unique UNIQUE (company_id, id);

CREATE TABLE branches (
  company_id BIGINT NOT NULL,
  id BIGSERIAL NOT NULL,
  name TEXT NOT NULL,
  address TEXT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT branches_pk PRIMARY KEY (company_id, id),
  CONSTRAINT branches_company_name_unique UNIQUE (company_id, name)
);

CREATE INDEX branches_company_id_idx ON branches (company_id);

CREATE TABLE categories (
  company_id BIGINT NOT NULL,
  id BIGSERIAL NOT NULL,
  name TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT categories_pk PRIMARY KEY (company_id, id),
  CONSTRAINT categories_company_name_unique UNIQUE (company_id, name)
);

CREATE INDEX categories_company_id_idx ON categories (company_id);

CREATE TABLE products (
  company_id BIGINT NOT NULL,
  id BIGSERIAL NOT NULL,
  category_id BIGINT NULL,
  sku TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT products_pk PRIMARY KEY (company_id, id),
  CONSTRAINT products_company_sku_unique UNIQUE (company_id, sku),
  CONSTRAINT products_category_fk FOREIGN KEY (company_id, category_id) REFERENCES categories (company_id, id)
);

CREATE INDEX products_company_id_idx ON products (company_id);
CREATE INDEX products_company_category_id_idx ON products (company_id, category_id);

CREATE TABLE inventory_items (
  company_id BIGINT NOT NULL,
  branch_id BIGINT NOT NULL,
  product_id BIGINT NOT NULL,
  quantity BIGINT NOT NULL DEFAULT 0,
  min_quantity BIGINT NOT NULL DEFAULT 0,
  updated_at BIGINT NOT NULL,
  CONSTRAINT inventory_items_pk PRIMARY KEY (company_id, branch_id, product_id),
  CONSTRAINT inventory_items_branch_fk FOREIGN KEY (company_id, branch_id) REFERENCES branches (company_id, id),
  CONSTRAINT inventory_items_product_fk FOREIGN KEY (company_id, product_id) REFERENCES products (company_id, id)
);

CREATE INDEX inventory_items_company_id_idx ON inventory_items (company_id);
CREATE INDEX inventory_items_branch_id_idx ON inventory_items (company_id, branch_id);
CREATE INDEX inventory_items_product_id_idx ON inventory_items (company_id, product_id);

CREATE TABLE inventory_movements (
  company_id BIGINT NOT NULL,
  id BIGSERIAL NOT NULL,
  branch_id BIGINT NOT NULL,
  product_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  movement_type TEXT NOT NULL,
  quantity BIGINT NOT NULL,
  reference TEXT NULL,
  created_at BIGINT NOT NULL,
  CONSTRAINT inventory_movements_pk PRIMARY KEY (company_id, id),
  CONSTRAINT inventory_movements_branch_fk FOREIGN KEY (company_id, branch_id) REFERENCES branches (company_id, id),
  CONSTRAINT inventory_movements_product_fk FOREIGN KEY (company_id, product_id) REFERENCES products (company_id, id),
  CONSTRAINT inventory_movements_user_fk FOREIGN KEY (company_id, user_id) REFERENCES users (company_id, id)
);

CREATE INDEX inventory_movements_company_id_idx ON inventory_movements (company_id);
CREATE INDEX inventory_movements_branch_id_idx ON inventory_movements (company_id, branch_id);
CREATE INDEX inventory_movements_product_id_idx ON inventory_movements (company_id, product_id);
CREATE INDEX inventory_movements_user_id_idx ON inventory_movements (company_id, user_id);
CREATE INDEX inventory_movements_created_at_idx ON inventory_movements (company_id, created_at);
