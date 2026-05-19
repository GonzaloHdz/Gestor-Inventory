Resumen técnico ejecutivo
========================

Arquitectura recomendada
------------------------

- Modelo: Clean Architecture / Hexagonal Architecture.
- Capas:
  - Presentación: UI web, APIs REST/GraphQL.
  - Aplicación: casos de uso, orquestación de flujos, validaciones de negocio.
  - Dominio: entidades, agregados, reglas de negocio y servicios del dominio.
  - Infraestructura: persistencia, autenticación, notificaciones, logging, auditoría.
- Principios:
  - Separación de responsabilidades.
  - Inversión de dependencias: las capas superiores dependen de interfaces.
  - Dominio independiente de la infraestructura.
  - Testabilidad y modularidad.

Esquema de base de datos para multi-tenant
------------------------------------------

- Base de datos relacional principal (por ejemplo PostgreSQL o SQL Server).
- Tablas clave con columnas de partición de tenant:
  - `companies` / `enterprises`.
  - `branches` / `locations`.
  - `users`.
  - `products`.
  - `suppliers`.
  - `inventory_items`.
  - `inventory_movements`.
  - `purchase_orders`.
  - `audit_logs`.
- Columnas obligatorias de aislamiento de datos:
  - `company_id` en todas las tablas de datos operativos.
  - `branch_id` en todas las tablas de inventario, movimientos y transacciones de stock.
- Índices compuestos con `company_id` y `branch_id` para consultas de tenant/sucursal.
- Restricciones:
  - clave única compuesta `company_id + sku` / `company_id + product_code`.
  - clave única compuesta `company_id + branch_id + product_id` para inventario por sucursal.
- Opciones avanzadas:
  - esquema compartido con columna `company_id` para data isolation basada en aplicación.
  - o esquemas separados por empresa si se exige mayor aislamiento y regulación.

Aislamiento de datos por empresa
--------------------------------

- La aplicación debe validar `company_id` en cada request y operación.
- Todas las consultas deben filtrar explícitamente por `company_id`.
- Las acciones de inventario deben tener `company_id` y `branch_id` firmados en cada entidad.
- Los usuarios se pertenecerán a una empresa y su sesión solo podrá acceder a datos de esa empresa.
- El control de acceso se aplica por empresa, sucursal, rol y permiso.
- Separación lógica de datos: cada tenant ve solo sus proveedores, productos, compras y movimientos.

Reglas de negocio críticas
--------------------------

- Stock no negativo:
  - Ninguna operación de salida puede finalizar si disminuye stock por debajo de cero.
  - La validación debe ejecutarse en el dominio y en la base de datos si es posible.
- Movimientos auditables:
  - Cada `inventory_movement` guarda usuario, fecha/hora, empresa, sucursal, producto, cantidad, tipo y referencia.
- Stock por sucursal independiente:
  - El inventario se gestiona con una fila por producto por sucursal.
  - El stock total de la empresa es la suma de cada sucursal.
- Entradas y salidas automáticas:
  - Las entradas incrementan stock y las salidas lo decrementan.
  - El ajuste del inventario debe quedar registrado como movimiento.
- Prohibición de duplicados de producto:
  - No puede existir un producto con el mismo SKU o código dentro de una misma empresa.
- Alertas de stock mínimo:
  - Cada producto tiene un umbral mínimo por empresa o sucursal.
  - El sistema debe generar alertas cuando `stock_actual < stock_minimo`.
- Compras actualizan inventario:
  - Cada orden de compra aprobada debe registrar entradas y ajustar existencias.
  - Las compras requieren proveedor obligatorio.
- Trazabilidad completa:
  - Cada cambio de stock se relaciona con una transacción, usuario, sucursal, empresa y motivo.
- Roles y permisos:
  - Roles base: Almacenista, Supervisor, Administrador, Superadministrador.
  - Permisos deben cubrir Productos, Inventario, Movimientos, Compras, Proveedores, Reportes, Usuarios, Sucursales, Configuración.
- Seguridad y auditoría desde el inicio:
  - Autenticación con manejo de contraseñas seguras y recuperación.
  - Registro de eventos críticos: login, cambios de stock, creación/edición/eliminación de registros.
  - Validación perimetral de tenant en cada endpoint.

Guía de implementación rápida
-----------------------------

- Definir entidades clave primero: Company, Branch, User, Role, Permission, Product, Supplier, InventoryItem, InventoryMovement, PurchaseOrder, AuditLog.
- Construir casos de uso MVP antes de extender con funciones avanzadas.
- Asegurar que cualquier endpoint o comando de dominio requiera `company_id` y valide `branch_id` cuando aplique.
- Mantener el flujo de datos consistente:
  - Identificación de tenant -> autorización -> validación de reglas de negocio -> persistencia -> auditoría.
- Priorizar el aislamiento de datos, la integridad del inventario y la no-negatividad del stock.
