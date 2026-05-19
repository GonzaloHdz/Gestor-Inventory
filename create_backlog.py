import argparse
import subprocess
import textwrap

EPICS = [
    {
        "title": "Autenticación y Seguridad Multiempresa",
        "description": "Implementar autenticación segura y multiempresa con roles, permisos y aislamiento de datos.",
        "features": [
            {
                "title": "Registro y login",
                "status": "MVP",
                "description": "Crear la base de autenticación con registro, inicio de sesión y recuperación de contraseña.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de usuarios con tenant y credenciales",
                        "description": "Definir el esquema de `users` que incluya `company_id`, correo, contraseña hash y estado.",
                        "acceptance_criteria": "- La tabla `users` contiene `company_id`, `email`, `password_hash`, `is_active` y `verified`\n- `email` es único por empresa\n- `company_id` nunca es nulo", 
                        "dependencies": "Ninguna",
                        "priority": "Alta",
                        "labels": ["backend", "database", "auth"]
                    },
                    {
                        "title": "Crear endpoint de registro de usuario",
                        "description": "Implementar API para registrar usuarios en la empresa correspondiente.",
                        "acceptance_criteria": "- Permite registrar usuario con `company_id`, `email`, `password` y `role_id`\n- Valida que el correo no exista para la misma empresa\n- Guarda la contraseña como hash seguro", 
                        "dependencies": "Diseñar tabla de usuarios con tenant y credenciales",
                        "priority": "Alta",
                        "labels": ["backend", "api", "auth"]
                    },
                    {
                        "title": "Crear endpoint de inicio de sesión",
                        "description": "Implementar autenticación con credenciales y generación de token de sesión.",
                        "acceptance_criteria": "- Permite login con `email`, `password` y `company_id`\n- Retorna token JWT o sesión válida\n- Rechaza credenciales incorrectas sin exponer información", 
                        "dependencies": "Crear endpoint de registro de usuario",
                        "priority": "Alta",
                        "labels": ["backend", "api", "auth"]
                    },
                    {
                        "title": "Implementar recuperación de contraseña",
                        "description": "Crear flujo backend para solicitar y restablecer contraseñas.",
                        "acceptance_criteria": "- Permite solicitar restablecimiento con correo válido\n- Genera token temporal y enlace seguro\n- Actualiza contraseña con validación de token", 
                        "dependencies": "Crear endpoint de login",
                        "priority": "Alta",
                        "labels": ["backend", "auth", "security"]
                    },
                    {
                        "title": "Registrar eventos de login y recuperación",
                        "description": "Loggear intentos de acceso y solicitudes de restablecimiento para auditoría.",
                        "acceptance_criteria": "- Se crea registro en `audit_logs` para intentos de login\n- Se crea registro para solicitudes de recuperación\n- Incluye `user_id`, `company_id`, `branch_id` y timestamp", 
                        "dependencies": "Implementar recuperación de contraseña",
                        "priority": "Media",
                        "labels": ["backend", "audit", "security"]
                    },
                    {
                        "title": "Crear política de expiración de sesión",
                        "description": "Definir y aplicar vencimiento de tokens o sesiones activas.",
                        "acceptance_criteria": "- Las sesiones expiran según configuración\n- Tokens vencidos son rechazados\n- El backend invalida sesiones expiradas en cada request", 
                        "dependencies": "Crear endpoint de inicio de sesión",
                        "priority": "Media",
                        "labels": ["backend", "auth", "security"]
                    },
                    {
                        "title": "Diseñar flujo de verificación de correo",
                        "description": "Crear la base para verificar cuentas mediante correo electrónico.",
                        "acceptance_criteria": "- Se permite marcar usuario como verificado\n- Se genera token de verificación\n- El flujo está preparado aunque no se implemente envío de correo inmediato", 
                        "dependencies": "Crear endpoint de registro de usuario",
                        "priority": "Media",
                        "labels": ["backend", "auth", "security"]
                    },
                    {
                        "title": "Agregar validación de contraseña segura",
                        "description": "Exigir reglas mínimas de complejidad para nuevas contraseñas.",
                        "acceptance_criteria": "- Las contraseñas cumplen longitud mínima y contenido\n- Los endpoints rechazan contraseñas débiles\n- El usuario recibe mensaje claro de error", 
                        "dependencies": "Crear endpoint de registro de usuario",
                        "priority": "Media",
                        "labels": ["backend", "security"]
                    }
                ]
            },
            {
                "title": "Roles y permisos",
                "status": "MVP",
                "description": "Definir roles base y permisos granulares para toda la plataforma.",
                "tasks": [
                    {
                        "title": "Diseñar tablas de roles y permisos",
                        "description": "Crear esquema para roles, permisos y asignaciones por usuario.",
                        "acceptance_criteria": "- Existen tablas `roles`, `permissions`, `role_permissions`, `user_roles`\n- Roles base incluyen Almacenista, Supervisor, Administrador, Superadministrador\n- Permisos están listados según módulos", 
                        "dependencies": "Diseñar tabla de usuarios con tenant y credenciales",
                        "priority": "Alta",
                        "labels": ["backend", "database", "auth"]
                    },
                    {
                        "title": "Implementar asignación de roles a usuarios",
                        "description": "Agregar API para asignar y revocar roles en contexto de empresa.",
                        "acceptance_criteria": "- Un usuario puede tener múltiples roles\n- Las asignaciones respetan el `company_id`\n- Solo administradores autorizados pueden cambiar roles", 
                        "dependencies": "Diseñar tablas de roles y permisos",
                        "priority": "Alta",
                        "labels": ["backend", "api", "auth"]
                    },
                    {
                        "title": "Crear middleware de autorización por permiso",
                        "description": "Validar permisos en cada endpoint según rol y empresa.",
                        "acceptance_criteria": "- El middleware verifica `company_id` y permisos\n- Rechaza acceso no autorizado con 403\n- Se puede aplicar por ruta o por acción", 
                        "dependencies": "Implementar asignación de roles a usuarios",
                        "priority": "Alta",
                        "labels": ["backend", "auth", "security"]
                    },
                    {
                        "title": "Crear endpoints de consulta de roles y permisos",
                        "description": "Permitir listar roles y permisos disponibles en la empresa.",
                        "acceptance_criteria": "- Retorna roles y permisos disponibles\n- Filtra resultados por empresa cuando aplica\n- Incluye descripción corta de cada permiso", 
                        "dependencies": "Diseñar tablas de roles y permisos",
                        "priority": "Media",
                        "labels": ["backend", "api", "admin"]
                    },
                    {
                        "title": "Validar permisos en operaciones de administración",
                        "description": "Asegurar que los cambios críticos respeten permisos de nivel administrativo.",
                        "acceptance_criteria": "- Solo usuarios con permisos específicos pueden crear empresas, sucursales o productos\n- Los endpoints de configuración se protegen adecuadamente\n- Se documentan los permisos requeridos", 
                        "dependencies": "Crear middleware de autorización por permiso",
                        "priority": "Alta",
                        "labels": ["backend", "auth", "security"]
                    },
                    {
                        "title": "Crear pruebas automatizadas de autorización",
                        "description": "Verificar que el middleware bloquea accesos indebidos y permite accesos válidos.",
                        "acceptance_criteria": "- Existen pruebas para cada rol base y permisos clave\n- Se valida acceso denegado en rutas restringidas\n- Se valida acceso permitido para roles adecuados", 
                        "dependencies": "Crear middleware de autorización por permiso",
                        "priority": "Media",
                        "labels": ["testing", "auth", "backend"]
                    }
                ]
            },
            {
                "title": "Aislamiento de datos por empresa y seguridad",
                "status": "MVP",
                "description": "Garantizar que todo acceso al dato valida la pertenencia a la empresa.",
                "tasks": [
                    {
                        "title": "Agregar `company_id` a todas las entidades operativas",
                        "description": "Asegurar que cada tabla crítica almacena el `company_id` para aislamiento.",
                        "acceptance_criteria": "- Todas las entidades operativas incluyen `company_id`\n- Las migraciones se actualizan para reflejar el aislamiento\n- No existen entidades compartidas sin tenant explícito", 
                        "dependencies": "Diseñar tablas de roles y permisos",
                        "priority": "Alta",
                        "labels": ["backend", "database", "security"]
                    },
                    {
                        "title": "Implementar validación de tenant en cada request",
                        "description": "Agregar capa que verifica el `company_id` asociado al usuario y el recurso.",
                        "acceptance_criteria": "- Cada request obtiene `company_id` del usuario autenticado\n- Se compara con el recurso solicitado\n- Se rechazan intentos de acceso cruzado entre empresas", 
                        "dependencies": "Crear middleware de autorización por permiso",
                        "priority": "Alta",
                        "labels": ["backend", "auth", "security"]
                    },
                    {
                        "title": "Asegurar que las consultas filtren por tenant y sucursal",
                        "description": "Implementar filtros obligatorios en consultas de inventario y datos sensibles.",
                        "acceptance_criteria": "- Todas las consultas devuelven resultados del `company_id` autenticado\n- `branch_id` se aplica en inventario y movimientos\n- Se evita uso de consultas globales sin filtro", 
                        "dependencies": "Agregar `company_id` a todas las entidades operativas",
                        "priority": "Alta",
                        "labels": ["backend", "database", "security"]
                    },
                    {
                        "title": "Registrar auditoría para accesos a datos multiempresa",
                        "description": "Grabar eventos de lectura y escritura de recursos sensibles por empresa.",
                        "acceptance_criteria": "- Se crea registro en `audit_logs` para accesos críticos\n- Incluye `company_id`, `user_id`, `resource` y `action`\n- Permite trazar accesos por tenant", 
                        "dependencies": "Implementar validación de tenant en cada request",
                        "priority": "Media",
                        "labels": ["backend", "audit", "security"]
                    }
                ]
            }
        ]
    },
    {
        "title": "Administración de Empresas y Sucursales",
        "description": "Gestionar la estructura multiempresa y la organización de sucursales con control de inventario local.",
        "features": [
            {
                "title": "Gestión de empresas",
                "status": "MVP",
                "description": "Crear entidades y APIs para administrar empresas aisladas.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de empresas",
                        "description": "Definir el esquema `companies` con datos básicos y configuración por negocio.",
                        "acceptance_criteria": "- Existen columnas `id`, `name`, `currency`, `timezone`, `created_at`\n- Se mantiene aislada del resto de los datos\n- `name` es único dentro del scope global", 
                        "dependencies": "Agregar `company_id` a todas las entidades operativas",
                        "priority": "Alta",
                        "labels": ["backend", "database", "admin"]
                    },
                    {
                        "title": "Crear endpoint para registrar empresas",
                        "description": "Permitir que superadministradores creen nuevas empresas en el sistema.",
                        "acceptance_criteria": "- Se crea empresa con datos obligatorios\n- Validación de nombre único\n- Devuelve `company_id` creado", 
                        "dependencies": "Diseñar tabla de empresas",
                        "priority": "Alta",
                        "labels": ["backend", "api", "admin"]
                    },
                    {
                        "title": "Implementar listado de empresas para superadmin",
                        "description": "Proveer API para que superadministradores consulten empresas activas.",
                        "acceptance_criteria": "- Retorna empresas con paginación\n- Solo usuarios superadmin acceden\n- Incluye estado y fecha de creación", 
                        "dependencies": "Crear endpoint para registrar empresas",
                        "priority": "Media",
                        "labels": ["backend", "api", "admin"]
                    },
                    {
                        "title": "Agregar validación de empresa en creación de recursos",
                        "description": "Verificar el `company_id` en todas las operaciones de creación de datos asociados.",
                        "acceptance_criteria": "- Al crear sucursales, proveedores, productos y movimiento se valida `company_id`\n- Se rechazan creaciones que no especifican tenant\n- Se bloquean inconsistencias entre empresa y recurso", 
                        "dependencies": "Crear endpoint para registrar empresas",
                        "priority": "Alta",
                        "labels": ["backend", "security", "database"]
                    },
                    {
                        "title": "Agregar pruebas de aislamiento de empresa",
                        "description": "Verificar mediante tests que un usuario no ve datos de otra empresa.",
                        "acceptance_criteria": "- Tests cubren al menos dos empresas\n- Intentos de acceso cruzado fallan con 403\n- Los resultados de consultas están filtrados por tenant", 
                        "dependencies": "Agregar validación de empresa en creación de recursos",
                        "priority": "Media",
                        "labels": ["testing", "security", "backend"]
                    }
                ]
            },
            {
                "title": "Gestión de sucursales",
                "status": "MVP",
                "description": "Administrar sucursales y su relación con inventario independiente.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de sucursales con `company_id`",
                        "description": "Crear el esquema `branches` incluyendo datos de ubicación y empresa.",
                        "acceptance_criteria": "- La tabla tiene `company_id`, `name`, `address`, `city`, `country`\n- `company_id` es clave foránea a `companies`\n- Existen índices en `company_id` y `name`", 
                        "dependencies": "Diseñar tabla de empresas",
                        "priority": "Alta",
                        "labels": ["backend", "database", "admin"]
                    },
                    {
                        "title": "Crear endpoint de creación de sucursal",
                        "description": "Permitir registrar sucursales para una empresa específica.",
                        "acceptance_criteria": "- Valida que la empresa exista\n- Guarda sucursal con `company_id` correcto\n- Devuelve `branch_id`", 
                        "dependencies": "Diseñar tabla de sucursales con `company_id`",
                        "priority": "Alta",
                        "labels": ["backend", "api", "admin"]
                    },
                    {
                        "title": "Crear endpoint de consulta de sucursales",
                        "description": "Listar sucursales de una empresa con filtros básicos.",
                        "acceptance_criteria": "- Retorna sucursales del `company_id` autenticado\n- Permite filtrar por ciudad y estado\n- No expone sucursales de otras empresas", 
                        "dependencies": "Crear endpoint de creación de sucursal",
                        "priority": "Media",
                        "labels": ["backend", "api", "admin"]
                    },
                    {
                        "title": "Implementar actualización y eliminación segura de sucursales",
                        "description": "Permitir editar datos de sucursal y marcar sucursal inactiva sin romper inventario.",
                        "acceptance_criteria": "- La sucursal se puede actualizar solo dentro de su empresa\n- La eliminación lógica marca inactiva\n- No se permite borrar sucursales con inventario asociado sin proceso previo", 
                        "dependencies": "Crear endpoint de consulta de sucursales",
                        "priority": "Media",
                        "labels": ["backend", "admin", "inventory"]
                    },
                    {
                        "title": "Agregar configuración de sucursal predeterminada para inventario",
                        "description": "Permitir establecer una sucursal principal para operaciones iniciales.",
                        "acceptance_criteria": "- Cada empresa puede tener una sucursal predeterminada\n- Se usa para crear inventario inicial y alertas\n- El campo se guarda en configuración de empresa", 
                        "dependencies": "Diseñar tabla de sucursales con `company_id`",
                        "priority": "Media",
                        "labels": ["backend", "admin"]
                    },
                    {
                        "title": "Crear pruebas de integración para sucursales multiempresa",
                        "description": "Verificar operaciones CRUD de sucursales con aislamiento tenant.",
                        "acceptance_criteria": "- Se prueba creación, actualización y listado\n- Un usuario no puede administrar sucursales de otra empresa\n- El branch_id se valida en todas las llamadas relevantes", 
                        "dependencies": "Implementar actualización y eliminación segura de sucursales",
                        "priority": "Media",
                        "labels": ["testing", "backend", "admin"]
                    }
                ]
            },
            {
                "title": "Configuración empresarial y de seguridad",
                "status": "MVP",
                "description": "Definir ajustes de empresa y políticas globales de acceso.",
                "tasks": [
                    {
                        "title": "Crear tabla de configuración por empresa",
                        "description": "Definir un almacén de parámetros para cada empresa.",
                        "acceptance_criteria": "- La tabla contiene `company_id`, `key`, `value`\n- Se puede guardar configuración de moneda, stock mínimo y notificaciones\n- Incluye restricciones por empresa", 
                        "dependencies": "Diseñar tabla de empresas",
                        "priority": "Media",
                        "labels": ["backend", "database", "admin"]
                    },
                    {
                        "title": "Implementar endpoint de configuración empresarial",
                        "description": "Permitir leer y actualizar parámetros específicos de la empresa.",
                        "acceptance_criteria": "- Devuelve configuración para el `company_id` autenticado\n- Permite actualizar solo claves autorizadas\n- Valida valores de configuración antes de guardar", 
                        "dependencies": "Crear tabla de configuración por empresa",
                        "priority": "Media",
                        "labels": ["backend", "api", "admin"]
                    },
                    {
                        "title": "Definir política de permisos por empresa y sucursal",
                        "description": "Crear reglas que limitan quién puede ver y editar recursos en cada nivel.",
                        "acceptance_criteria": "- Se documenta la jerarquía de permisos\n- Los endpoints aplican validación de empresa y sucursal\n- No se permite el acceso cruzado multitenant", 
                        "dependencies": "Implementar validación de tenant en cada request",
                        "priority": "Alta",
                        "labels": ["backend", "auth", "security"]
                    }
                ]
            }
        ]
    },
    {
        "title": "Catálogo de Productos y Proveedores",
        "description": "Gestionar proveedores, categorías y catálogo básico de productos con reglas de SKU y duplicidad.",
        "features": [
            {
                "title": "Gestión de proveedores",
                "status": "MVP",
                "description": "Implementar proveedores y su relación obligatoria con compras.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de proveedores con `company_id`",
                        "description": "Definir esquema `suppliers` que soporte datos de contacto y clasificación.",
                        "acceptance_criteria": "- Incluye `company_id`, `name`, `document_id`, `contact_email`, `phone`\n- Se marca proveedor como activo/inactivo\n- `company_id` es clave foránea válida", 
                        "dependencies": "Diseñar tabla de empresas",
                        "priority": "Alta",
                        "labels": ["backend", "database", "purchases"]
                    },
                    {
                        "title": "Crear endpoint de registro de proveedor",
                        "description": "Permitir agregar proveedores para la empresa autenticada.",
                        "acceptance_criteria": "- Valida datos obligatorios\n- El proveedor se asocia al `company_id` correcto\n- Devuelve proveedor creado", 
                        "dependencies": "Diseñar tabla de proveedores con `company_id`",
                        "priority": "Alta",
                        "labels": ["backend", "api", "purchases"]
                    },
                    {
                        "title": "Implementar listado de proveedores por empresa",
                        "description": "Listar proveedores activos de la empresa con filtros básicos.",
                        "acceptance_criteria": "- Filtra por `company_id` autenticado\n- Permite buscar por nombre o documento\n- No devuelve proveedores de otras empresas", 
                        "dependencies": "Crear endpoint de registro de proveedor",
                        "priority": "Media",
                        "labels": ["backend", "api", "purchases"]
                    },
                    {
                        "title": "Agregar validación de proveedor obligatorio en compras",
                        "description": "Asegurar que cada orden de compra requiere un proveedor asociado.",
                        "acceptance_criteria": "- Las órdenes de compra fallan sin proveedor\n- El proveedor pertenece a la misma empresa\n- El campo no es opcional en el modelo de compra", 
                        "dependencies": "Diseñar tabla de proveedores con `company_id`",
                        "priority": "Alta",
                        "labels": ["backend", "purchases", "inventory"]
                    },
                    {
                        "title": "Crear pruebas para creación y consulta de proveedores",
                        "description": "Verificar que solo proveedores de la misma empresa son accesibles.",
                        "acceptance_criteria": "- Pruebas cubren creación y listado\n- Un usuario no ve proveedores de otra empresa\n- Las búsquedas retornan resultados esperados", 
                        "dependencies": "Implementar listado de proveedores por empresa",
                        "priority": "Media",
                        "labels": ["testing", "backend", "purchases"]
                    },
                    {
                        "title": "Crear endpoint de actualización de proveedores",
                        "description": "Permitir editar datos de proveedores sin cambiar su empresa.",
                        "acceptance_criteria": "- Los cambios solo afectan al proveedor dentro de la empresa\n- No se permite cambiar `company_id`\n- Valida campos actualizados", 
                        "dependencies": "Crear endpoint de registro de proveedor",
                        "priority": "Media",
                        "labels": ["backend", "api", "purchases"]
                    },
                    {
                        "title": "Permitir inactivar proveedores en vez de borrar",
                        "description": "Agregar lógica para desactivar proveedores y mantener trazabilidad.",
                        "acceptance_criteria": "- Se puede marcar proveedor como inactivo\n- Los proveedores inactivos no aparecen en listas por defecto\n- Las compras existentes conservan el proveedor asociado", 
                        "dependencies": "Crear endpoint de actualización de proveedores",
                        "priority": "Media",
                        "labels": ["backend", "purchases", "audit"]
                    }
                ]
            },
            {
                "title": "Gestión de productos y categorías",
                "status": "MVP",
                "description": "Implementar catálogo de productos con categorías y control de duplicados por empresa.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de categorías por empresa",
                        "description": "Crear `categories` para clasificar productos dentro de cada empresa.",
                        "acceptance_criteria": "- Incluye `company_id`, `name`, `description`\n- `name` es único por empresa\n- Las categorías pueden estar activas o inactivas", 
                        "dependencies": "Diseñar tabla de empresas",
                        "priority": "Media",
                        "labels": ["backend", "database", "catalog"]
                    },
                    {
                        "title": "Diseñar tabla de productos con validación de SKU",
                        "description": "Definir `products` con SKU único por empresa y campos de inventario clave.",
                        "acceptance_criteria": "- Incluye `company_id`, `sku`, `name`, `category_id`, `stock_minimum`\n- El par `company_id + sku` es único\n- `category_id` es foráneo a `categories` en la misma empresa", 
                        "dependencies": "Diseñar tabla de categorías por empresa",
                        "priority": "Alta",
                        "labels": ["backend", "database", "inventory"]
                    },
                    {
                        "title": "Crear endpoint de registro de producto",
                        "description": "Permitir agregar productos al catálogo de una empresa con categoría y SKU.",
                        "acceptance_criteria": "- Valida SKU único para la empresa\n- Guarda categoría y datos obligatorios\n- Devuelve producto creado con `product_id`", 
                        "dependencies": "Diseñar tabla de productos con validación de SKU",
                        "priority": "Alta",
                        "labels": ["backend", "api", "catalog"]
                    },
                    {
                        "title": "Crear endpoint de actualización de producto",
                        "description": "Permitir editar producto sin crear duplicados de SKU.",
                        "acceptance_criteria": "- El SKU no puede duplicarse dentro de la empresa\n- Se puede actualizar nombre, categoría y stock mínimo\n- Mantiene historial de auditoría para cambios", 
                        "dependencies": "Crear endpoint de registro de producto",
                        "priority": "Alta",
                        "labels": ["backend", "api", "catalog"]
                    },
                    {
                        "title": "Implementar validación de duplicado de producto por empresa",
                        "description": "Asegurar que no haya productos repetidos por SKU o código en la misma empresa.",
                        "acceptance_criteria": "- Se rechazan registros con SKU existente\n- Se rechazan actualizaciones que causen duplicados\n- El mensaje de error es claro", 
                        "dependencies": "Crear endpoint de registro de producto",
                        "priority": "Alta",
                        "labels": ["backend", "inventory", "security"]
                    },
                    {
                        "title": "Crear endpoint de listado de productos por empresa",
                        "description": "Proveer API para consultar el catálogo filtrado por tenant.",
                        "acceptance_criteria": "- Lista productos del `company_id` autenticado\n- Permite paginación y filtro por categoría\n- No devuelve productos de otras empresas", 
                        "dependencies": "Crear endpoint de registro de producto",
                        "priority": "Media",
                        "labels": ["backend", "api", "catalog"]
                    },
                    {
                        "title": "Agregar gestión de códigos alternos y descripciones",
                        "description": "Permitir guardar código interno alternativo o descripción larga para productos.",
                        "acceptance_criteria": "- El modelo acepta códigos o códigos de barras adicionales\n- El endpoint permite editar la descripción larga\n- La búsqueda usa código alterno cuando está disponible", 
                        "dependencies": "Crear endpoint de registro de producto",
                        "priority": "Media",
                        "labels": ["backend", "catalog", "ux"]
                    },
                    {
                        "title": "Crear pruebas de validación de SKU y categoría",
                        "description": "Verificar creación y actualización de productos con restricciones de empresa.",
                        "acceptance_criteria": "- Se prueba el bloqueo de SKUs duplicados\n- Se prueba asociación incorrecta de categoría por empresa\n- Los productos pertenecen al tenant correcto", 
                        "dependencies": "Implementar validación de duplicado de producto por empresa",
                        "priority": "Media",
                        "labels": ["testing", "backend", "inventory"]
                    },
                    {
                        "title": "Crear endpoint de consulta de categorías",
                        "description": "Listar categorías disponibles para la empresa autenticada.",
                        "acceptance_criteria": "- Filtra por `company_id`\n- Incluye categoría activa/inactiva\n- No expone categorías de otras empresas", 
                        "dependencies": "Diseñar tabla de categorías por empresa",
                        "priority": "Media",
                        "labels": ["backend", "api", "catalog"]
                    }
                ]
            },
            {
                "title": "Catálogo básico y búsqueda",
                "status": "MVP",
                "description": "Construir funcionalidades básicas de búsqueda y filtro del catálogo.",
                "tasks": [
                    {
                        "title": "Implementar búsqueda de productos por nombre o SKU",
                        "description": "Agregar búsqueda que funcione por texto y código de producto.",
                        "acceptance_criteria": "- Permite buscar dentro de la empresa autenticada\n- Soporta coincidencia parcial por nombre y SKU\n- Los resultados no muestran datos de otros tenants", 
                        "dependencies": "Crear endpoint de listado de productos por empresa",
                        "priority": "Media",
                        "labels": ["backend", "api", "ux"]
                    },
                    {
                        "title": "Agregar filtro de productos por categoría",
                        "description": "Permitir filtrar el catálogo por la categoría seleccionada.",
                        "acceptance_criteria": "- Filtro devuelve productos de la categoría dentro del tenant\n- Combina con búsqueda por texto\n- No requiere exposición de categorías de otra empresa", 
                        "dependencies": "Implementar búsqueda de productos por nombre o SKU",
                        "priority": "Media",
                        "labels": ["backend", "api", "ux"]
                    },
                    {
                        "title": "Implementar paginación básica en el catálogo",
                        "description": "Agregar paginación en los listados de productos y proveedores.",
                        "acceptance_criteria": "- Devuelve resultados paginados\n- Incluye total y página actual\n- Reduce carga en consultas grandes", 
                        "dependencies": "Crear endpoint de listado de productos por empresa",
                        "priority": "Media",
                        "labels": ["backend", "api", "performance"]
                    },
                    {
                        "title": "Crear endpoint de detalle de producto",
                        "description": "Proporcionar información completa de un producto por ID.",
                        "acceptance_criteria": "- Devuelve datos del producto si pertenece a la empresa\n- Incluye categoría y stock mínimo\n- Rechaza acceso a productos de otras empresas", 
                        "dependencies": "Crear endpoint de listado de productos por empresa",
                        "priority": "Media",
                        "labels": ["backend", "api", "catalog"]
                    }
                ]
            }
        ]
    },
    {
        "title": "Inventario y Movimientos",
        "description": "Controlar inventario por sucursal, registrar movimientos y garantizar stock no negativo con auditoría completa.",
        "features": [
            {
                "title": "Control básico de inventario",
                "status": "MVP",
                "description": "Implementar inventario por sucursal y reglas de stock mínimo y no negativo.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de inventario por sucursal",
                        "description": "Crear `inventory_items` que almacene stock actual por producto y sucursal.",
                        "acceptance_criteria": "- Incluye `company_id`, `branch_id`, `product_id`, `quantity`, `stock_minimum`\n- La combinación `company_id + branch_id + product_id` es única\n- Se indexa por `branch_id` y `product_id`", 
                        "dependencies": "Diseñar tabla de productos con validación de SKU",
                        "priority": "Alta",
                        "labels": ["backend", "database", "inventory"]
                    },
                    {
                        "title": "Crear endpoint de consulta de inventario por sucursal",
                        "description": "Permitir ver stock actual de productos dentro de una sucursal.",
                        "acceptance_criteria": "- Filtra resultados por `company_id` y `branch_id`\n- Devuelve stock actual y stock mínimo\n- No revela sucursales de otras empresas", 
                        "dependencies": "Diseñar tabla de inventario por sucursal",
                        "priority": "Alta",
                        "labels": ["backend", "api", "inventory"]
                    },
                    {
                        "title": "Implementar actualización de stock con entradas y salidas",
                        "description": "Ajustar stock al crear movimientos manuales y registrar el resultado.",
                        "acceptance_criteria": "- Las entradas incrementan stock\n- Las salidas decrementan stock\n- El inventario se actualiza en `inventory_items` tras cada movimiento", 
                        "dependencies": "Crear endpoint de consulta de inventario por sucursal",
                        "priority": "Alta",
                        "labels": ["backend", "inventory"]
                    },
                    {
                        "title": "Validar stock no negativo en el dominio",
                        "description": "Bloquear cualquier salida que deje el stock por debajo de cero.",
                        "acceptance_criteria": "- Se rechazan movimientos de salida si `quantity > stock_actual`\n- Regresa error con motivo claro\n- No se realiza ningún cambio en inventario cuando falla la validación", 
                        "dependencies": "Implementar actualización de stock con entradas y salidas",
                        "priority": "Alta",
                        "labels": ["backend", "inventory", "security"]
                    },
                    {
                        "title": "Agregar regla de stock mínimo por producto",
                        "description": "Registrar umbrales para alertas cuando el stock se reduzca." ,
                        "acceptance_criteria": "- Cada producto tiene `stock_minimum`\n- El valor se almacena en inventario por sucursal\n- Se puede actualizar el umbral en el producto o inventario", 
                        "dependencies": "Diseñar tabla de inventario por sucursal",
                        "priority": "Media",
                        "labels": ["backend", "inventory"]
                    },
                    {
                        "title": "Implementar consulta de stock total consolidado",
                        "description": "Calcular stock agregado de un producto en todas las sucursales de la empresa.",
                        "acceptance_criteria": "- Suma stock de todas las sucursales del tenant\n- Devuelve total y desglose por sucursal\n- Respeta aislamiento de empresa", 
                        "dependencies": "Crear endpoint de consulta de inventario por sucursal",
                        "priority": "Media",
                        "labels": ["backend", "reports", "inventory"]
                    },
                    {
                        "title": "Crear pruebas de inventario por sucursal y stock no negativo",
                        "description": "Verificar que el inventario por sucursal no permita valores negativos y se calcula correctamente.",
                        "acceptance_criteria": "- Se prueba la creación y actualización de inventario\n- Se rechazan salidas que deben causar stock negativo\n- Los cálculos de stock total son correctos", 
                        "dependencies": "Validar stock no negativo en el dominio",
                        "priority": "Media",
                        "labels": ["testing", "inventory", "backend"]
                    }
                ]
            },
            {
                "title": "Entradas y salidas manuales",
                "status": "MVP",
                "description": "Registrar movimientos manuales de inventario con auditoría y control por usuario.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de movimientos de inventario",
                        "description": "Crear `inventory_movements` con tipo, cantidad, usuario y referencias de branch.",
                        "acceptance_criteria": "- Incluye `company_id`, `branch_id`, `product_id`, `user_id`, `movement_type`, `quantity`, `reference`, `created_at`\n- El movimiento almacena si fue entrada o salida\n- Se puede consultar por usuario y sucursal", 
                        "dependencies": "Diseñar tabla de inventario por sucursal",
                        "priority": "Alta",
                        "labels": ["backend", "database", "inventory"]
                    },
                    {
                        "title": "Crear endpoint para registrar entrada manual",
                        "description": "Permitir añadir stock mediante movimiento de tipo entrada.",
                        "acceptance_criteria": "- Aumenta `inventory_items.quantity`\n- Crea registro en `inventory_movements`\n- Incluye `company_id`, `branch_id`, `product_id`, `user_id`", 
                        "dependencies": "Diseñar tabla de movimientos de inventario",
                        "priority": "Alta",
                        "labels": ["backend", "api", "inventory"]
                    },
                    {
                        "title": "Crear endpoint para registrar salida manual",
                        "description": "Permitir disminuir stock mediante movimiento de tipo salida.",
                        "acceptance_criteria": "- Disminuye stock si hay suficiente cantidad\n- Crea registro de movimiento\n- Rechaza salidas que causen stock negativo", 
                        "dependencies": "Diseñar tabla de movimientos de inventario",
                        "priority": "Alta",
                        "labels": ["backend", "api", "inventory"]
                    },
                    {
                        "title": "Agregar validación de cantidad positiva",
                        "description": "Exigir que todas las entradas y salidas usen cantidades mayores a cero.",
                        "acceptance_criteria": "- Rechaza cantidades negativas o cero\n- Aplica en entradas y salidas\n- Genera mensaje de error claro", 
                        "dependencies": "Crear endpoint para registrar entrada manual",
                        "priority": "Alta",
                        "labels": ["backend", "validation", "inventory"]
                    },
                    {
                        "title": "Registrar usuario y sucursal en cada movimiento",
                        "description": "Garantizar trazabilidad completa de cada ajuste de stock.",
                        "acceptance_criteria": "- `inventory_movements` incluye `user_id`, `company_id`, `branch_id` y timestamp\n- Se usa el usuario autenticado\n- La sucursal asociada es la del movimiento", 
                        "dependencies": "Diseñar tabla de movimientos de inventario",
                        "priority": "Alta",
                        "labels": ["backend", "audit", "inventory"]
                    },
                    {
                        "title": "Agregar referencia de motivo para cada movimiento",
                        "description": "Permitir registrar motivo, documento o nota para cada entrada/salida.",
                        "acceptance_criteria": "- El movimiento acepta campo `reference` o `note`\n- El motivo se guarda junto con el registro\n- Se puede consultar en el historial", 
                        "dependencies": "Crear endpoint para registrar salida manual",
                        "priority": "Media",
                        "labels": ["backend", "inventory", "audit"]
                    },
                    {
                        "title": "Implementar listado de movimientos por sucursal",
                        "description": "Crear API para consultar historial de movimientos de inventario.",
                        "acceptance_criteria": "- Filtra por `company_id` y `branch_id`\n- Permite rango de fechas y tipo de movimiento\n- No expone movimientos de otras empresas", 
                        "dependencies": "Crear endpoint para registrar salida manual",
                        "priority": "Media",
                        "labels": ["backend", "api", "inventory"]
                    },
                    {
                        "title": "Crear pruebas de registro de movimientos manuales",
                        "description": "Verificar entradas, salidas, validaciones de cantidad y auditoría.",
                        "acceptance_criteria": "- Se prueban entradas y salidas exitosas\n- Se prueba rechazo por stock negativo\n- El movimiento guarda campos obligatorios", 
                        "dependencies": "Registrar usuario y sucursal en cada movimiento",
                        "priority": "Media",
                        "labels": ["testing", "inventory", "backend"]
                    }
                ]
            },
            {
                "title": "Auditoría de inventario y trazabilidad",
                "status": "MVP",
                "description": "Garantizar la trazabilidad completa para movimientos e inventario por sucursal.",
                "tasks": [
                    {
                        "title": "Diseñar tabla de auditoría para cambios críticos",
                        "description": "Crear `audit_logs` para registrar eventos de cambio en el sistema.",
                        "acceptance_criteria": "- Incluye `company_id`, `branch_id`, `user_id`, `resource`, `action`, `details`, `created_at`\n- Registra cambios CRUD y movimientos críticos\n- Permite filtrar por tenant y usuario", 
                        "dependencies": "Diseñar tabla de movimientos de inventario",
                        "priority": "Alta",
                        "labels": ["backend", "database", "audit"]
                    },
                    {
                        "title": "Registrar auditoría al modificar inventario y productos",
                        "description": "Agregar logging automático cuando se crean o actualizan datos clave.",
                        "acceptance_criteria": "- Se registra auditoría en creación/actualización/eliminación de productos, proveedores y movimientos\n- Incluye usuario y empresa\n- No registra datos de otras empresas", 
                        "dependencies": "Diseñar tabla de auditoría para cambios críticos",
                        "priority": "Media",
                        "labels": ["backend", "audit", "inventory"]
                    },
                    {
                        "title": "Implementar consulta de auditoría para admin",
                        "description": "Permitir a administradores revisar log de eventos por tenant.",
                        "acceptance_criteria": "- Devuelve logs filtrados por `company_id`\n- Permite búsqueda por usuario, recurso y acción\n- No expone eventos de otros tenants", 
                        "dependencies": "Registrar auditoría al modificar inventario y productos",
                        "priority": "Media",
                        "labels": ["backend", "api", "audit"]
                    },
                    {
                        "title": "Agregar validación de branch en auditoría",
                        "description": "Incluir sucursal en los registros de auditoría de movimientos.",
                        "acceptance_criteria": "- Cada movimiento auditado incluye `branch_id`\n- Los registros se asocian correctamente con la sucursal de la acción\n- La auditoría no pierde contexto de ubicación", 
                        "dependencies": "Implementar consulta de auditoría para admin",
                        "priority": "Media",
                        "labels": ["backend", "audit", "inventory"]
                    },
                    {
                        "title": "Crear pruebas de auditoría para movimientos de inventario",
                        "description": "Verificar que se genera auditoría al crear entradas y salidas.",
                        "acceptance_criteria": "- Se registra evento por cada movimiento creado\n- Audits incluyen usuario, empresa y sucursal\n- Los registros son consultables por admin", 
                        "dependencies": "Agregar validación de branch en auditoría",
                        "priority": "Media",
                        "labels": ["testing", "audit", "backend"]
                    },
                    {
                        "title": "Implementar reconciliación de inventario inicial",
                        "description": "Agregar función para configurar inventario inicial de productos en sucursales.",
                        "acceptance_criteria": "- Se puede establecer stock inicial en un inventario existente\n- Registra los movimientos iniciales en `inventory_movements`\n- El inventario refleja los valores iniciales correctamente", 
                        "dependencies": "Diseñar tabla de inventario por sucursal",
                        "priority": "Media",
                        "labels": ["backend", "inventory", "audit"]
                    }
                ]
            }
        ]
    },
    {
        "title": "Reportes, Alertas y Panel Administrativo",
        "description": "Ofrecer visibilidad de inventario, alertas tempranas y paneles administrativos para empresas y sucursales.",
        "features": [
            {
                "title": "Alertas de stock básico",
                "status": "MVP",
                "description": "Detectar y listar productos con stock bajo para cada sucursal.",
                "tasks": [
                    {
                        "title": "Crear cálculo de alerta de stock mínimo",
                        "description": "Detectar productos cuya cantidad actual es menor que el mínimo definido.",
                        "acceptance_criteria": "- Compara `inventory_items.quantity` con `stock_minimum`\n- Marca productos en alerta cuando la cantidad es menor\n- El cálculo es por sucursal y empresa", 
                        "dependencies": "Agregar regla de stock mínimo por producto",
                        "priority": "Alta",
                        "labels": ["backend", "inventory", "reports"]
                    },
                    {
                        "title": "Implementar endpoint de alertas de stock",
                        "description": "Proveer API que lista productos en alerta para la empresa y sucursal actual.",
                        "acceptance_criteria": "- Filtra por `company_id` y `branch_id`\n- Retorna productos con stock bajo\n- Devuelve cantidad actual y mínimo esperado", 
                        "dependencies": "Crear cálculo de alerta de stock mínimo",
                        "priority": "Alta",
                        "labels": ["backend", "api", "inventory"]
                    },
                    {
                        "title": "Registrar alertas en flujo de movimiento",
                        "description": "Generar alerta después de cada movimiento si el stock queda bajo el umbral.",
                        "acceptance_criteria": "- Tras una salida el sistema revisa el stock mínimo\n- Si el stock queda bajo, se marca alerta\n- La alerta es visible en el endpoint de alertas", 
                        "dependencies": "Implementar endpoint de alertas de stock",
                        "priority": "Media",
                        "labels": ["backend", "inventory", "notifications"]
                    },
                    {
                        "title": "Crear pruebas de alertas de stock",
                        "description": "Verificar detección y listado de productos en stock bajo.",
                        "acceptance_criteria": "- Los productos con stock menor al mínimo aparecen en alertas\n- Las alertas no incluyen productos por encima del umbral\n- El filtrado usa tenant y sucursal correctos", 
                        "dependencies": "Registrar alertas en flujo de movimiento",
                        "priority": "Media",
                        "labels": ["testing", "inventory", "reports"]
                    },
                    {
                        "title": "Definir stock mínimo por sucursal",
                        "description": "Permitir que el valor mínimo se configure por inventario de sucursal.",
                        "acceptance_criteria": "- Cada inventario por sucursal almacena su propio `stock_minimum`\n- El endpoint de inventario muestra el umbral por sucursal\n- Las alertas se calculan con ese valor", 
                        "dependencies": "Agregar regla de stock mínimo por producto",
                        "priority": "Media",
                        "labels": ["backend", "inventory", "admin"]
                    }
                ]
            },
            {
                "title": "Reportes básicos",
                "status": "MVP",
                "description": "Construir reportes esenciales de inventario y movimientos para administración.",
                "tasks": [
                    {
                        "title": "Implementar reporte de estado de inventario",
                        "description": "Crear API que devuelva stock actual y mínimos por sucursal.",
                        "acceptance_criteria": "- Devuelve stock por sucursal para la empresa autenticada\n- Incluye productos en alerta y no alerta\n- Respeta aislamiento multiempresa", 
                        "dependencies": "Crear endpoint de consulta de inventario por sucursal",
                        "priority": "Alta",
                        "labels": ["backend", "reports", "inventory"]
                    },
                    {
                        "title": "Implementar reporte de movimientos de inventario",
                        "description": "Crear API que liste movimientos por fecha, sucursal y tipo.",
                        "acceptance_criteria": "- Filtra por `company_id`, `branch_id`, rango de fechas y tipo\n- Incluye entradas y salidas\n- No devuelve movimientos de otros tenants", 
                        "dependencies": "Implementar listado de movimientos por sucursal",
                        "priority": "Alta",
                        "labels": ["backend", "reports", "inventory"]
                    },
                    {
                        "title": "Crear reporte de proveedores y compras básicas",
                        "description": "Construir API que muestre compras por proveedor y estado de abastecimiento.",
                        "acceptance_criteria": "- Devuelve compras agrupadas por proveedor del tenant\n- Muestra cantidades y fechas\n- Requiere proveedor asociado y empresa correcta", 
                        "dependencies": "Agregar validación de proveedor obligatorio en compras",
                        "priority": "Media",
                        "labels": ["backend", "reports", "purchases"]
                    },
                    {
                        "title": "Implementar exportación básica a CSV para reportes",
                        "description": "Permitir descargar resultados de reportes en formato CSV.",
                        "acceptance_criteria": "- Los reportes pueden exportarse como CSV\n- Los datos respetan aislamiento tenant\n- Los encabezados son claros y consistentes", 
                        "dependencies": "Implementar reporte de estado de inventario",
                        "priority": "Media",
                        "labels": ["backend", "reports", "integration"]
                    },
                    {
                        "title": "Crear pruebas de reportes básicos",
                        "description": "Verificar que los reportes devuelven datos correctos y aislados por empresa.",
                        "acceptance_criteria": "- Los reportes devuelven información correcta para datos de prueba\n- No se mezclan datos de distintas empresas\n- Los filtros funcionan como se espera", 
                        "dependencies": "Implementar reporte de movimientos de inventario",
                        "priority": "Media",
                        "labels": ["testing", "reports", "backend"]
                    }
                ]
            },
            {
                "title": "Panel administrativo y auditoría",
                "status": "MVP",
                "description": "Proveer una vista administrativa con métricas de inventario y logs de auditoría.",
                "tasks": [
                    {
                        "title": "Crear endpoint de dashboard administrativo",
                        "description": "Implementar API que devuelva métricas clave de inventario y sucursales.",
                        "acceptance_criteria": "- Devuelve métricas de stock, alertas y sucursales\n- Filtra por empresa autenticada\n- Solo usuarios con permiso de admin acceden", 
                        "dependencies": "Implementar reporte de estado de inventario",
                        "priority": "Alta",
                        "labels": ["backend", "admin", "reports"]
                    },
                    {
                        "title": "Crear endpoint de auditoría para administradores",
                        "description": "Permitir consultar registros de auditoría de la empresa.",
                        "acceptance_criteria": "- Filtra logs por `company_id`\n- Permite buscar por usuario y recurso\n- Solo usuarios autorizados pueden acceder", 
                        "dependencies": "Implementar consulta de auditoría para admin",
                        "priority": "Alta",
                        "labels": ["backend", "audit", "admin"]
                    },
                    {
                        "title": "Agregar endpoint de gestión de usuarios internos",
                        "description": "Permitir listar y administrar usuarios de la empresa desde el backend.",
                        "acceptance_criteria": "- Lista usuarios del tenant actual\n- No expone usuarios de otras empresas\n- Permite activar/inactivar cuentas", 
                        "dependencies": "Implementar listado de empresas para superadmin",
                        "priority": "Media",
                        "labels": ["backend", "admin", "users"]
                    },
                    {
                        "title": "Crear endpoint de roles y permisos para admin",
                        "description": "Permitir ver y ajustar roles y permisos desde la administración.",
                        "acceptance_criteria": "- Muestra roles disponibles y permisos asociados\n- Solo admins pueden consultar esta información\n- El endpoint respeta tenant y no mezcla datos", 
                        "dependencies": "Crear endpoints de consulta de roles y permisos",
                        "priority": "Media",
                        "labels": ["backend", "admin", "auth"]
                    },
                    {
                        "title": "Implementar pruebas del panel administrativo",
                        "description": "Verificar que los endpoints administrativos entregan datos correctos y aislados.",
                        "acceptance_criteria": "- Las métricas del dashboard son consistentes con los datos de prueba\n- Usuarios de otra empresa no obtienen resultados\n- Los roles se validan correctamente", 
                        "dependencies": "Crear endpoint de dashboard administrativo",
                        "priority": "Media",
                        "labels": ["testing", "admin", "backend"]
                    }
                ]
            }
        ]
    },
    {
        "title": "Expansión Avanzada y Conectividad",
        "description": "Agregar capacidades avanzadas y futuras integraciones con proveedores, IA y movilidad.",
        "features": [
            {
                "title": "Integraciones y movilidad",
                "status": "POST-MVP",
                "description": "Preparar el sistema para integraciones externas y aplicaciones móviles.",
                "tasks": [
                    {
                        "title": "Diseñar endpoints de API preparatoria para mobile",
                        "description": "Crear rutas de consulta de inventario y movimientos listas para apps móviles.",
                        "acceptance_criteria": "- Existen endpoints dedicados para consumo móvil\n- Devuelven datos paginados y compactos\n- Respetan aislamiento tenant", 
                        "dependencies": "Crear endpoint de detalle de producto",
                        "priority": "Media",
                        "labels": ["backend", "api", "integration"]
                    },
                    {
                        "title": "Diseñar integración stub con proveedor externo",
                        "description": "Crear el modelo de integración para conectarse a proveedores externos futuros.",
                        "acceptance_criteria": "- Se define interfaz de proveedor externo\n- Se implementa stub con datos de prueba\n- La integración está desacoplada del dominio principal", 
                        "dependencies": "Agregar validación de proveedor obligatorio en compras",
                        "priority": "Media",
                        "labels": ["backend", "integration", "purchases"]
                    },
                    {
                        "title": "Definir soporte para escaneo de código de barras / RFID",
                        "description": "Preparar el modelo de datos y la API para captura de productos mediante escaneo.",
                        "acceptance_criteria": "- Se define modelo de `barcode` o `rfid` para productos\n- Existe endpoint de búsqueda por código escaneado\n- La lógica es extensible a hardware móvil", 
                        "dependencies": "Diseñar tabla de productos con validación de SKU",
                        "priority": "Media",
                        "labels": ["backend", "inventory", "ux"]
                    },
                    {
                        "title": "Crear pruebas de la API móvil preparatoria",
                        "description": "Validar que los endpoints móviles devuelvan datos correctos y escalen con paginación.",
                        "acceptance_criteria": "- Las rutas móviles funcionan con datos de prueba\n- Los límites de paginación son respetados\n- Se valida el aislamiento tenant", 
                        "dependencies": "Diseñar endpoints de API preparatoria para mobile",
                        "priority": "Baja",
                        "labels": ["testing", "integration", "backend"]
                    }
                ]
            },
            {
                "title": "Inventario avanzado",
                "status": "POST-MVP",
                "description": "Agregar modelos de lotes, caducidad y series para inventario especializado.",
                "tasks": [
                    {
                        "title": "Diseñar soporte de lotes y caducidad",
                        "description": "Crear modelo de `batches` que incluya lotes, fecha de vencimiento y stock por lote.",
                        "acceptance_criteria": "- Se define entidad de lotes vinculada a productos y sucursales\n- Incluye `expiry_date` y cantidad\n- Permite rastrear stock por lote", 
                        "dependencies": "Diseñar tabla de inventario por sucursal",
                        "priority": "Media",
                        "labels": ["backend", "inventory", "database"]
                    },
                    {
                        "title": "Diseñar soporte de inventario por serie",
                        "description": "Agregar modelo para rastrear productos por número de serie cuando aplique.",
                        "acceptance_criteria": "- Se define entidad de series asociada a productos y sucursales\n- Se puede registrar cada unidad con su serie\n- La trazabilidad es completa por serie", 
                        "dependencies": "Diseñar soporte de lotes y caducidad",
                        "priority": "Baja",
                        "labels": ["backend", "inventory", "audit"]
                    },
                    {
                        "title": "Implementar alertas de caducidad y lote vencido",
                        "description": "Permitir detectar lotes próximos a vencer y vencidos en inventario.",
                        "acceptance_criteria": "- Se identifican lotes con fecha de vencimiento próxima\n- Se genera alerta separada del stock mínimo\n- Las alertas respetan tenant y sucursal", 
                        "dependencies": "Diseñar soporte de lotes y caducidad",
                        "priority": "Baja",
                        "labels": ["backend", "inventory", "reports"]
                    },
                    {
                        "title": "Crear pruebas para lotes y caducidad",
                        "description": "Verificar el modelo y la detección de caducidad en inventario avanzado.",
                        "acceptance_criteria": "- Los lotes se crean correctamente\n- Se detectan caducidades según fecha\n- El aislamiento tenant se mantiene", 
                        "dependencies": "Diseñar soporte de lotes y caducidad",
                        "priority": "Baja",
                        "labels": ["testing", "inventory", "backend"]
                    }
                ]
            },
            {
                "title": "Automatización y predicción",
                "status": "POST-MVP",
                "description": "Preparar capacidades de IA y automatización para demanda y reabastecimiento.",
                "tasks": [
                    {
                        "title": "Definir interfaz de predicción de demanda",
                        "description": "Implementar un servicio stub para futuras predicciones de inventario.",
                        "acceptance_criteria": "- Se define contrato de entrada y salida para predicción\n- El stub devuelve recomendaciones de reordenamiento\n- La funcionalidad está desacoplada del dominio principal", 
                        "dependencies": "Implementar integración stub con proveedor externo",
                        "priority": "Baja",
                        "labels": ["backend", "integration", "reports"]
                    },
                    {
                        "title": "Diseñar reglas de reabastecimiento automático",
                        "description": "Crear modelo para reglas de reordenamiento basadas en stock mínimo y demanda esperada.",
                        "acceptance_criteria": "- Se define entidad de reglas de reorder\n- Soporta trigger cuando el stock está bajo el umbral\n- El modelo puede usar información histórica en el futuro", 
                        "dependencies": "Definir interfaz de predicción de demanda",
                        "priority": "Baja",
                        "labels": ["backend", "inventory", "automation"]
                    },
                    {
                        "title": "Crear pruebas de los stubs de automatización",
                        "description": "Verificar que las interfaces de predicción y reabastecimiento funcionan como stubs.",
                        "acceptance_criteria": "- Los stubs devuelven resultados consistentes en pruebas\n- Las reglas de reabastecimiento son evaluables\n- La implementación no rompe el flujo MVP", 
                        "dependencies": "Diseñar reglas de reabastecimiento automático",
                        "priority": "Baja",
                        "labels": ["testing", "backend", "integration"]
                    },
                    {
                        "title": "Documentar la API de automatización y predicción",
                        "description": "Crear documentación básica del contrato de la API para predicción y reabastecimiento.",
                        "acceptance_criteria": "- Existe documentación clara de endpoints y payloads\n- Se define el formato de solicitud y respuesta\n- La documentación está disponible para el equipo de desarrollo", 
                        "dependencies": "Definir interfaz de predicción de demanda",
                        "priority": "Baja",
                        "labels": ["backend", "documentation", "integration"]
                    }
                ]
            }
        ]
    }
]


def build_issue_body(task, feature, epic):
    return textwrap.dedent(f"""
        **EPIC:** {epic['title']}
        **FEATURE:** {feature['title']} ({feature['status']})

        **Descripción:** {task['description']}

        **Criterios de aceptación:**
        {task['acceptance_criteria']}

        **Dependencias:** {task['dependencies']}

        **Prioridad:** {task['priority']}
        """)


# Labels required in the target repository. The script will ensure they exist before creating issues.
LABELS_TO_CREATE = ['backend', 'frontend', 'database', 'auth', 'inventory', 'purchases', 'reports', 'admin', 'security', 'testing', 'api', 'ux', 'integration', 'MVP', 'POST-MVP', 'audit'
, 'catalog', 'performance', 'refactor', 'documentation', 'research', 'wontfix', 'duplicate', 'invalid', 'help wanted', 'good first issue'
'validation', 'bug', 'enhancement', 'question', 'discussion', 'priority: high', 'priority: medium', 'priority: low','validation','notifications', 'users',
'automation']

def ensure_labels_exist(repo=None, dry_run=False):
    """Create required labels in the target repository using `gh label create --force`.

    If `repo` is provided, the `--repo` flag is passed to `gh`.
    """
    for label in LABELS_TO_CREATE:
        command = ["gh", "label", "create", label, "--force"]
        if repo:
            command.extend(["--repo", repo])
        if dry_run:
            print("DRY RUN:", " ".join(shlex_quote(arg) for arg in command))
        else:
            subprocess.run(command, check=True)



def create_issue(title, body, labels, repo=None, assignee=None, dry_run=False):
    command = ["gh", "issue", "create", "--title", title, "--body", body]
    if labels:
        command.extend(["--label", ",".join(labels)])
    if repo:
        command.extend(["--repo", repo])
    if assignee:
        command.extend(["--assignee", assignee])

    if dry_run:
        print("DRY RUN:", " ".join(shlex_quote(arg) for arg in command))
        return

    subprocess.run(command, check=True)


def shlex_quote(value):
    return f'"{value.replace("\"", "\\\"")}"'


def main():
    parser = argparse.ArgumentParser(description="Crear backlog de GitHub issues a partir de EPICS estructurados.")
    parser.add_argument("--repo", help="Repositorio destino en formato OWNER/REPO")
    parser.add_argument("--assignee", help="Asignar issues a un usuario de GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Imprimir los comandos sin ejecutarlos")
    args = parser.parse_args()
    # Ensure required labels exist in the target repository to avoid 'label not found' errors.
    ensure_labels_exist(repo=args.repo, dry_run=args.dry_run)

    issue_count = 0
    for epic in EPICS:
        for feature in epic["features"]:
            for task in feature["tasks"]:
                title = task["title"]
                body = build_issue_body(task, feature, epic)
                create_issue(title, body, task.get("labels", []), repo=args.repo, assignee=args.assignee, dry_run=args.dry_run)
                issue_count += 1

    print(f"Procesadas {issue_count} issues.")


if __name__ == "__main__":
    main()
