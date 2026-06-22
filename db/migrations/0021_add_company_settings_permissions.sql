INSERT INTO permissions (id, code, description)
VALUES
  (701, 'configuracion:leer', 'Leer configuración'),
  (702, 'configuracion:editar', 'Editar configuración')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('configuracion:leer', 'configuracion:editar')
WHERE r.name IN ('Administrador', 'Superadministrador')
ON CONFLICT DO NOTHING;
