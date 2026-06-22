INSERT INTO permissions (id, code, description)
VALUES
  (812, 'sucursales:editar', 'Editar sucursales'),
  (813, 'sucursales:eliminar', 'Eliminar (desactivar) sucursales')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (company_id, role_id, permission_id)
SELECT r.company_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('sucursales:editar', 'sucursales:eliminar')
WHERE r.name IN ('Administrador', 'Superadministrador')
ON CONFLICT DO NOTHING;
