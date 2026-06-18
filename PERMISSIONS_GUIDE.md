PERMISSIONS_GUIDE (MVP)
======================

Principios
----------

- Seguridad por defecto: toda operación crítica debe estar protegida por un permiso explícito.
- Multiempresa: las operaciones deben ejecutarse en el `company_id` del token (y validarse contra la BD cuando aplique).
- Endpoints administrativos (`/api/admin/*`): si no existe permiso definido para una ruta crítica, se deniega con 403 (Forbidden).

Mapa de permisos por operación (MVP)
-----------------------------------

RBAC / Administración

- Listar roles (GET /api/admin/roles): roles:leer
- Listar permisos (GET /api/admin/permissions): roles:leer
- Asignar rol a usuario (POST /api/admin/user-roles/assign): roles:modificar
- Revocar rol a usuario (POST /api/admin/user-roles/revoke): roles:modificar

Usuarios

- Crear usuario (admin): usuarios:crear
- Listar usuarios (admin): usuarios:listar
- Editar usuario (admin): usuarios:editar
- Eliminar usuario (admin): usuarios:eliminar

Empresas / Sucursales (planificado)

- Crear empresa (POST /api/admin/companies): empresas:crear
- Listar empresas (GET /api/admin/companies): empresas:leer
- Editar empresa (PATCH /api/admin/companies/default-branch): empresas:editar
- Crear sucursal (POST /api/admin/branches): sucursal:crear
- Listar sucursales (GET /api/admin/branches): sucursales:leer
- Editar sucursal: sucursal:editar

Inventario / Productos (planificado)

- Modificar inventario (entradas/salidas/ajustes): inventario:modificar
- Crear producto (POST /api/admin/products): productos:crear
- Modificar producto: productos:modificar
- Eliminar producto: productos:eliminar
