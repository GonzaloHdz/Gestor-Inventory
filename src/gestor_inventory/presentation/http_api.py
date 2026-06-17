import json
import time
from urllib.parse import parse_qs, urlparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from gestor_inventory.application.login_user import LoginRequest, login_user
from gestor_inventory.application.categories import (
    CreateCategoryRequest,
    GetCategoryRequest,
    create_category,
    get_category,
)
from gestor_inventory.application.create_company import CreateCompanyRequest, create_company
from gestor_inventory.application.inventory import (
    ListInventoryMovementsRequest,
    ListInventoryRequest,
    RegisterInventoryMovementRequest,
    list_inventory,
    list_inventory_movements,
    register_inventory_movement,
)
from gestor_inventory.application.list_rbac import (
    ListRolesRequest,
    list_permissions,
    list_roles,
)
from gestor_inventory.application.products import (
    CreateProductRequest,
    ListProductsRequest,
    create_product,
    list_products,
)
from gestor_inventory.application.manage_user_roles import (
    AssignUserRoleRequest,
    RevokeUserRoleRequest,
    assign_user_role,
    revoke_user_role,
)
from gestor_inventory.application.request_password_reset import RequestPasswordResetRequest, request_password_reset
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.application.reset_password import ResetPasswordRequest, reset_password
from gestor_inventory.application.verify_email import VerifyEmailRequest, verify_email
from gestor_inventory.domain.errors import (
    CompanyNameAlreadyExistsError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    NotFoundError,
    PasswordResetTokenExpiredError,
    PasswordResetTokenInvalidError,
    ValidationError,
)
from gestor_inventory.security.jwt import verify_jwt_hs256


class HttpApiHandler(BaseHTTPRequestHandler):
    repo = None
    jwt_secret = None
    jwt_expiration_minutes = 60

    def end_headers(self):
        origin = self.headers.get("Origin")
        if origin == "http://127.0.0.1:5500":
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT.value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/me":
            self._handle_me()
            return
        if parsed.path == "/api/inventory/movements":
            self._handle_list_inventory_movements(parsed.query)
            return
        if parsed.path == "/api/products":
            self._handle_list_products()
            return
        if parsed.path == "/api/auth/verify-email":
            self._handle_verify_email(parsed.query)
            return
        if parsed.path == "/api/inventory":
            self._handle_list_inventory(parsed.query)
            return
        if parsed.path == "/api/admin/roles":
            self._handle_list_roles()
            return
        if parsed.path == "/api/admin/permissions":
            self._handle_list_permissions()
            return
        if parsed.path.startswith("/api/admin/categories/"):
            self._handle_get_category(parsed.path)
            return
        if parsed.path.startswith("/api/admin/"):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "message": "Prohibido"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/api/users/register":
            self._handle_register()
            return
        if self.path == "/api/auth/login":
            self._handle_login()
            return
        if self.path == "/api/inventory/movements":
            self._handle_register_inventory_movement()
            return
        if self.path == "/api/products":
            self._handle_create_product()
            return
        if self.path == "/api/admin/user-roles/assign":
            self._handle_assign_user_role()
            return
        if self.path == "/api/admin/user-roles/revoke":
            self._handle_revoke_user_role()
            return
        if self.path == "/api/admin/companies":
            self._handle_create_company()
            return
        if self.path == "/api/admin/categories":
            self._handle_create_category()
            return
        if self.path == "/api/auth/password-reset/request":
            self._handle_password_reset_request()
            return
        if self.path == "/api/auth/password-reset/confirm":
            self._handle_password_reset_confirm()
            return
        if self.path.startswith("/api/admin/"):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "message": "Prohibido"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _handle_create_company(self) -> None:
        try:
            payload = self._read_json()
            authz = self._require_permissions({"empresas:crear"})
            if authz is None:
                return
            res = create_company(
                self.repo,
                CreateCompanyRequest(
                    name=payload["name"],
                    currency=payload["currency"],
                    timezone=payload["timezone"],
                ),
            )
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except CompanyNameAlreadyExistsError:
            self._send_json(HTTPStatus.CONFLICT, {"error": "company_name_exists"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._audit_data(
            authz,
            action="CREATE",
            resource="empresas",
            details=json.dumps(
                {
                    "new_company_id": res.company.id,
                    "name": res.company.name,
                    "currency": res.company.currency,
                    "timezone": res.company.timezone,
                },
                separators=(",", ":"),
            ),
        )
        self._send_json(HTTPStatus.CREATED, {"company_id": res.company.id})

    def _handle_register(self) -> None:
        try:
            payload = self._read_json()
            req = RegisterUserRequest(
                company_id=payload["company_id"],
                email=payload["email"],
                password=payload["password"],
                role_id=payload["role_id"],
            )
            host = self.headers.get("Host", "127.0.0.1")
            base_url = f"http://{host}"
            res = register_user(self.repo, req, base_url=base_url)
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except EmailAlreadyExistsError:
            self._send_json(HTTPStatus.CONFLICT, {"error": "email_already_exists"})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(
            HTTPStatus.CREATED,
            {
                "id": res.user.id,
                "company_id": res.user.company_id,
                "email": res.user.email,
                "is_active": res.user.is_active,
                "verified": res.user.verified,
                "role_id": res.role_id,
                "verification_url": res.verification_url,
            },
        )

    def _handle_login(self) -> None:
        try:
            payload = self._read_json()
            req = LoginRequest(
                company_id=payload["company_id"],
                email=payload["email"],
                password=payload["password"],
            )
            if not isinstance(self.jwt_secret, str) or not self.jwt_secret:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
                return
            res = login_user(
                self.repo,
                req,
                jwt_secret=self.jwt_secret,
                access_token_ttl_seconds=int(self.jwt_expiration_minutes) * 60,
            )
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except (ValidationError, InvalidCredentialsError):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid_credentials", "message": "Credenciales inválidas"})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(HTTPStatus.OK, {"access_token": res.access_token, "token_type": "bearer"})

    def _handle_me(self) -> None:
        payload = self._require_auth_payload()
        if payload is None:
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "sub": payload.get("sub"),
                "company_id": payload.get("company_id"),
                "email": payload.get("email"),
                "iat": payload.get("iat"),
                "exp": payload.get("exp"),
            },
        )

    def _handle_verify_email(self, query: str) -> None:
        try:
            params = parse_qs(query, keep_blank_values=True)
            company_id_raw = (params.get("company_id") or [None])[0]
            token_raw = (params.get("token") or [None])[0]
            req = VerifyEmailRequest(company_id=int(company_id_raw), token=token_raw)
            verify_email(self.repo, req)
        except (TypeError, ValueError, KeyError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(HTTPStatus.OK, {"status": "ok"})

    def _handle_list_roles(self) -> None:
        try:
            authz = self._require_permissions({"roles:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            res = list_roles(self.repo, ListRolesRequest(company_id=company_id))
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "roles": [
                    {"company_id": r.company_id, "id": r.id, "name": r.name, "is_system": r.is_system} for r in res.roles
                ]
            },
        )

    def _handle_list_permissions(self) -> None:
        try:
            authz = self._require_permissions({"roles:leer"})
            if authz is None:
                return
            res = list_permissions(self.repo)
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "permissions": [
                    {"id": p.id, "code": p.code, "description": p.description} for p in res.permissions
                ]
            },
        )

    def _handle_list_inventory(self, query: str) -> None:
        try:
            authz = self._require_permissions({"inventario:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            branch_id_raw = (params.get("branch_id") or [None])[0]
            branch_id = int(branch_id_raw)
            res = list_inventory(self.repo, ListInventoryRequest(company_id=company_id, branch_id=branch_id))
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except NotFoundError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._audit_data(
            authz,
            action="READ",
            resource="inventario",
            details=json.dumps({"branch_id": int(branch_id), "items": len(res.items)}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "items": [
                    {
                        "company_id": i.company_id,
                        "branch_id": i.branch_id,
                        "product_id": i.product_id,
                        "quantity": i.quantity,
                        "min_quantity": i.min_quantity,
                        "updated_at": i.updated_at,
                    }
                    for i in res.items
                ]
            },
        )

    def _handle_list_products(self) -> None:
        try:
            authz = self._require_permissions({"productos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            res = list_products(self.repo, ListProductsRequest(company_id=company_id))
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "products": [
                    {
                        "company_id": p.company_id,
                        "id": p.id,
                        "category_id": p.category_id,
                        "sku": p.sku,
                        "name": p.name,
                        "description": p.description,
                        "is_active": p.is_active,
                    }
                    for p in res.products
                ]
            },
        )

    def _handle_list_inventory_movements(self, query: str) -> None:
        try:
            authz = self._require_permissions({"movimientos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            branch_id_raw = (params.get("branch_id") or [None])[0]
            limit_raw = (params.get("limit") or [50])[0]
            res = list_inventory_movements(
                self.repo,
                ListInventoryMovementsRequest(
                    company_id=company_id,
                    branch_id=int(branch_id_raw),
                    limit=int(limit_raw),
                ),
            )
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except NotFoundError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "movements": [
                    {
                        "company_id": m.company_id,
                        "id": m.id,
                        "branch_id": m.branch_id,
                        "product_id": m.product_id,
                        "user_id": m.user_id,
                        "movement_type": m.movement_type,
                        "quantity": m.quantity,
                        "reference": m.reference,
                        "created_at": m.created_at,
                    }
                    for m in res.movements
                ]
            },
        )

    def _handle_register_inventory_movement(self) -> None:
        try:
            payload = self._read_json()
            authz = self._require_permissions({"movimientos:crear"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            user_id = int(authz.get("sub"))
            res = register_inventory_movement(
                self.repo,
                RegisterInventoryMovementRequest(
                    company_id=company_id,
                    branch_id=int(payload["branch_id"]),
                    product_id=int(payload["product_id"]),
                    user_id=user_id,
                    movement_type=payload["movement_type"],
                    quantity=int(payload["quantity"]),
                    reference=payload.get("reference"),
                ),
            )
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except NotFoundError as e:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "message": str(e)})
            return
        except ValidationError as e:
            message = str(e)
            if "stock insuficiente" in message.lower():
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"error": "negative_stock_rejected", "message": "No hay suficiente stock disponible. Operacion rechazada."},
                )
                return
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": message})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        item = res.item
        movement = res.movement
        self._audit_data(
            authz,
            action="CREATE",
            resource="movimientos",
            details=json.dumps(
                {
                    "branch_id": movement.branch_id,
                    "product_id": movement.product_id,
                    "movement_type": movement.movement_type,
                    "quantity": movement.quantity,
                    "result_quantity": item.quantity,
                },
                separators=(",", ":"),
            ),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {
                "item": {
                    "company_id": item.company_id,
                    "branch_id": item.branch_id,
                    "product_id": item.product_id,
                    "quantity": item.quantity,
                    "min_quantity": item.min_quantity,
                    "updated_at": item.updated_at,
                },
                "movement": {
                    "company_id": movement.company_id,
                    "id": movement.id,
                    "branch_id": movement.branch_id,
                    "product_id": movement.product_id,
                    "user_id": movement.user_id,
                    "movement_type": movement.movement_type,
                    "quantity": movement.quantity,
                    "reference": movement.reference,
                    "created_at": movement.created_at,
                },
            },
        )

    def _handle_create_product(self) -> None:
        try:
            payload = self._read_json()
            payload_company_id = payload.get("company_id")
            authz = self._require_permissions(
                {"productos:crear"},
                company_id=(int(payload_company_id) if payload_company_id is not None else None),
            )
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            category_id_raw = payload.get("category_id")
            res = create_product(
                self.repo,
                CreateProductRequest(
                    company_id=company_id,
                    category_id=(int(category_id_raw) if category_id_raw is not None else None),
                    sku=payload["sku"],
                    name=payload["name"],
                    description=payload.get("description"),
                ),
            )
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            status = HTTPStatus.CONFLICT if "sku" in str(e).lower() and "existe" in str(e).lower() else HTTPStatus.BAD_REQUEST
            error = "sku_already_exists" if status == HTTPStatus.CONFLICT else "validation_error"
            payload = {"error": error, "message": str(e)}
            self._send_json(status, payload)
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        p = res.product
        self._audit_data(
            authz,
            action="CREATE",
            resource="productos",
            details=json.dumps({"product_id": p.id, "sku": p.sku, "name": p.name}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {
                "product": {
                    "company_id": p.company_id,
                    "id": p.id,
                    "category_id": p.category_id,
                    "sku": p.sku,
                    "name": p.name,
                    "description": p.description,
                    "is_active": p.is_active,
                }
            },
        )

    def _handle_get_category(self, path: str) -> None:
        try:
            authz = self._require_permissions({"productos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            raw_id = path.removeprefix("/api/admin/categories/").strip("/")
            category_id = int(raw_id)
            res = get_category(self.repo, GetCategoryRequest(company_id=company_id, category_id=category_id))
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except NotFoundError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        c = res.category
        self._send_json(
            HTTPStatus.OK,
            {"category": {"company_id": c.company_id, "id": c.id, "name": c.name, "is_active": c.is_active}},
        )

    def _handle_create_category(self) -> None:
        try:
            payload = self._read_json()
            payload_company_id = payload.get("company_id")
            authz = self._require_permissions(
                {"productos:crear"},
                company_id=(int(payload_company_id) if payload_company_id is not None else None),
            )
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            res = create_category(self.repo, CreateCategoryRequest(company_id=company_id, name=payload["name"]))
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        c = res.category
        self._audit_data(
            authz,
            action="CREATE",
            resource="categorias",
            details=json.dumps({"category_id": c.id, "name": c.name}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {"category": {"company_id": c.company_id, "id": c.id, "name": c.name, "is_active": c.is_active}},
        )

    def _handle_password_reset_request(self) -> None:
        try:
            payload = self._read_json()
            req = RequestPasswordResetRequest(company_id=payload["company_id"], email=payload["email"])
            res = request_password_reset(self.repo, req)
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(
            HTTPStatus.OK,
            {"status": "ok", "reset_token": res.reset_token, "reset_url": res.reset_url},
        )

    def _handle_password_reset_confirm(self) -> None:
        try:
            payload = self._read_json()
            req = ResetPasswordRequest(
                company_id=payload["company_id"],
                token=payload["token"],
                new_password=payload["new_password"],
            )
            reset_password(self.repo, req)
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except PasswordResetTokenExpiredError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "token_expired"})
            return
        except PasswordResetTokenInvalidError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_token"})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._send_json(HTTPStatus.OK, {"status": "ok"})

    def _handle_assign_user_role(self) -> None:
        try:
            payload = self._read_json()
            company_id = int(payload["company_id"])
            authz = self._require_permissions({"roles:modificar"}, company_id=company_id)
            if authz is None:
                return
            req = AssignUserRoleRequest(
                company_id=company_id,
                user_id=int(payload["user_id"]),
                role_id=int(payload["role_id"]),
            )
            res = assign_user_role(self.repo, req)
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except NotFoundError as e:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "message": str(e)})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._audit_data(
            authz,
            action="CREATE",
            resource="roles",
            details=json.dumps(
                {"target_user_id": int(req.user_id), "role_id": int(req.role_id), "changed": bool(res.changed)},
                separators=(",", ":"),
            ),
        )
        self._send_json(HTTPStatus.OK, {"status": "ok", "changed": res.changed})

    def _handle_revoke_user_role(self) -> None:
        try:
            payload = self._read_json()
            company_id = int(payload["company_id"])
            authz = self._require_permissions({"roles:modificar"}, company_id=company_id)
            if authz is None:
                return
            req = RevokeUserRoleRequest(
                company_id=company_id,
                user_id=int(payload["user_id"]),
                role_id=int(payload["role_id"]),
            )
            res = revoke_user_role(self.repo, req)
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except (TypeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
            return
        except NotFoundError as e:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "message": str(e)})
            return
        except ValidationError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "validation_error", "message": str(e)})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except Exception:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return

        self._audit_data(
            authz,
            action="DELETE",
            resource="roles",
            details=json.dumps(
                {"target_user_id": int(req.user_id), "role_id": int(req.role_id), "changed": bool(res.changed)},
                separators=(",", ":"),
            ),
        )
        self._send_json(HTTPStatus.OK, {"status": "ok", "changed": res.changed})

    def log_message(self, format, *args):
        return

    def _require_auth_payload(self) -> dict | None:
        if not isinstance(self.jwt_secret, str) or not self.jwt_secret:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
            return None
        auth = self.headers.get("Authorization", "")
        if not isinstance(auth, str) or not auth.startswith("Bearer "):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized", "message": "No autorizado"})
            return None
        token = auth.removeprefix("Bearer ").strip()
        if not token:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized", "message": "No autorizado"})
            return None
        try:
            return verify_jwt_hs256(token, secret=self.jwt_secret)
        except Exception:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized", "message": "No autorizado"})
            return None

    def _require_permissions(
        self,
        required_permissions: set[str],
        *,
        company_id: int | None = None,
    ) -> dict | None:
        payload = self._require_auth_payload()
        if payload is None:
            return None

        token_company_id = payload.get("company_id")
        if not isinstance(token_company_id, int) or int(token_company_id) <= 0:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "message": "Prohibido"})
            return None
        if company_id is not None and int(token_company_id) != int(company_id):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "message": "Prohibido"})
            return None

        sub = payload.get("sub")
        try:
            actor_user_id = int(sub)
        except Exception:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "message": "Prohibido"})
            return None

        if not hasattr(self.repo, "list_user_permission_codes"):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "message": "Prohibido"})
            return None

        permissions = set(self.repo.list_user_permission_codes(company_id=int(token_company_id), user_id=actor_user_id))
        if required_permissions and not required_permissions.issubset(permissions):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "message": "Prohibido"})
            return None

        return payload

    def _audit_data(self, authz_payload: dict, *, action: str, resource: str, details: str | None) -> None:
        if not hasattr(self.repo, "create_data_audit_log"):
            raise RuntimeError("audit repository not configured")
        company_id = authz_payload.get("company_id")
        sub = authz_payload.get("sub")
        self.repo.create_data_audit_log(
            company_id=int(company_id),
            user_id=int(sub),
            action=str(action),
            resource=str(resource),
            details=str(details) if details is not None else None,
            timestamp=int(time.time()),
        )

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b""
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, status: HTTPStatus, body: dict) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
