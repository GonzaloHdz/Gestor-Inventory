INSERT INTO permissions (id, code, description)
VALUES (301, 'productos:leer', 'Leer productos')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.code = 'productos:leer'
WHERE r.name IN ('Almacenista', 'Supervisor', 'Administrador', 'Superadministrador')
ON CONFLICT DO NOTHING;

