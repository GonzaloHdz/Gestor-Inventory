CREATE TABLE user_roles (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  CONSTRAINT user_roles_company_user_role_unique UNIQUE (company_id, user_id, role_id),
  CONSTRAINT user_roles_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX user_roles_company_id_idx ON user_roles (company_id);
CREATE INDEX user_roles_user_id_idx ON user_roles (user_id);
