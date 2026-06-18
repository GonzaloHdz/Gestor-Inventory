INSERT INTO permissions (id, code, description)
VALUES (400, 'proveedores:crear', 'Crear proveedores')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.code = 'proveedores:crear'
WHERE r.name IN ('Administrador', 'Superadministrador')
ON CONFLICT DO NOTHING;
