CREATE TABLE roles (
  company_id BIGINT NOT NULL,
  id BIGSERIAL NOT NULL,
  name TEXT NOT NULL,
  is_system BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT roles_pk PRIMARY KEY (company_id, id),
  CONSTRAINT roles_company_name_unique UNIQUE (company_id, name)
);

CREATE INDEX roles_company_id_idx ON roles (company_id);

CREATE TABLE permissions (
  id BIGSERIAL PRIMARY KEY,
  code TEXT NOT NULL,
  description TEXT NULL,
  CONSTRAINT permissions_code_unique UNIQUE (code)
);

CREATE TABLE role_permissions (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  permission_id BIGINT NOT NULL,
  CONSTRAINT role_permissions_company_role_perm_unique UNIQUE (company_id, role_id, permission_id),
  CONSTRAINT role_permissions_role_fk FOREIGN KEY (company_id, role_id) REFERENCES roles (company_id, id),
  CONSTRAINT role_permissions_permission_fk FOREIGN KEY (permission_id) REFERENCES permissions (id)
);

CREATE INDEX role_permissions_company_id_idx ON role_permissions (company_id);
CREATE INDEX role_permissions_role_id_idx ON role_permissions (company_id, role_id);
CREATE INDEX role_permissions_permission_id_idx ON role_permissions (permission_id);

ALTER TABLE user_roles
  ADD CONSTRAINT user_roles_role_fk FOREIGN KEY (company_id, role_id) REFERENCES roles (company_id, id);

CREATE INDEX user_roles_role_id_idx ON user_roles (company_id, role_id);

INSERT INTO roles (company_id, id, name, is_system)
VALUES
  (1, 10, 'Almacenista', TRUE),
  (1, 11, 'Supervisor', TRUE),
  (1, 12, 'Administrador', TRUE),
  (1, 13, 'Superadministrador', TRUE),
  (2, 10, 'Almacenista', TRUE),
  (2, 11, 'Supervisor', TRUE),
  (2, 12, 'Administrador', TRUE),
  (2, 13, 'Superadministrador', TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (id, code, description)
VALUES
  (100, 'usuarios:crear', 'Crear usuarios'),
  (101, 'usuarios:listar', 'Listar usuarios'),
  (102, 'usuarios:editar', 'Editar usuarios'),
  (103, 'usuarios:eliminar', 'Eliminar usuarios'),
  (110, 'roles:leer', 'Leer roles'),
  (111, 'roles:modificar', 'Crear/editar roles y asignaciones'),
  (200, 'inventario:leer', 'Leer inventario'),
  (201, 'inventario:modificar', 'Modificar inventario'),
  (210, 'movimientos:leer', 'Leer movimientos de inventario'),
  (211, 'movimientos:crear', 'Crear movimientos de inventario'),
  (300, 'productos:crear', 'Crear productos'),
  (301, 'productos:leer', 'Leer productos'),
  (302, 'productos:modificar', 'Modificar productos'),
  (303, 'productos:eliminar', 'Eliminar productos'),
  (400, 'proveedores:crear', 'Crear proveedores'),
  (401, 'proveedores:leer', 'Leer proveedores'),
  (402, 'proveedores:modificar', 'Modificar proveedores'),
  (403, 'proveedores:eliminar', 'Eliminar proveedores'),
  (500, 'compras:crear', 'Crear órdenes de compra'),
  (501, 'compras:leer', 'Leer órdenes de compra'),
  (502, 'compras:aprobar', 'Aprobar órdenes de compra'),
  (600, 'reportes:leer', 'Leer reportes'),
  (700, 'configuracion:modificar', 'Modificar configuración')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('inventario:leer', 'movimientos:leer', 'productos:leer')
WHERE r.name = 'Almacenista' AND r.company_id IN (1, 2)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p
  ON p.code IN ('inventario:leer', 'inventario:modificar', 'movimientos:leer', 'movimientos:crear', 'productos:leer', 'reportes:leer')
WHERE r.name = 'Supervisor' AND r.company_id IN (1, 2)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p ON TRUE
WHERE r.name IN ('Administrador', 'Superadministrador') AND r.company_id IN (1, 2)
ON CONFLICT DO NOTHING;
