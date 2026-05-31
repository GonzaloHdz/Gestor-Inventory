INSERT INTO permissions (id, code, description)
VALUES (800, 'empresas:crear', 'Crear empresas')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.code = 'empresas:crear'
WHERE r.name = 'Superadministrador'
ON CONFLICT DO NOTHING;
