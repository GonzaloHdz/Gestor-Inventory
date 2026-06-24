import cgi
import json
import os
import struct
import time
from urllib.parse import parse_qs, urlparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from gestor_inventory.application.login_user import LoginRequest, login_user
from gestor_inventory.application.logout_user import LogoutRequest, logout_user
from gestor_inventory.application.refresh_access_token import RefreshAccessTokenRequest, refresh_access_token
from gestor_inventory.application.resend_verification_email import (
    ResendVerificationEmailRequest,
    resend_verification_email,
)
from gestor_inventory.application.categories import (
    CreateCategoryRequest,
    GetCategoryRequest,
    create_category,
    get_category,
)
from gestor_inventory.application.branches import CreateBranchRequest, create_branch
from gestor_inventory.application.create_company import CreateCompanyRequest, create_company
from gestor_inventory.application.create_internal_user import CreateInternalUserRequest, create_internal_user
from gestor_inventory.application.set_company_default_branch import SetCompanyDefaultBranchRequest, set_company_default_branch
from gestor_inventory.application.deactivate_branch import DeactivateBranchRequest, deactivate_branch
from gestor_inventory.application.get_company_settings import GetCompanySettingsRequest, get_company_settings
from gestor_inventory.application.inventory import (
    ListInventoryMovementsRequest,
    ListInventoryRequest,
    RegisterInventoryMovementRequest,
    list_inventory,
    list_inventory_movements,
    register_inventory_movement,
)
from gestor_inventory.application.list_branches import ListBranchesRequest, list_branches
from gestor_inventory.application.sat.list_sat_catalogs import (
    ListSatCatalogRequest,
    list_sat_productos_use_case,
    list_sat_regimenes_use_case,
    list_sat_unidades_use_case,
)
from gestor_inventory.application.list_rbac import (
    ListRolesRequest,
    list_permissions,
    list_roles,
)
from gestor_inventory.application.list_users import ListUsersRequest, list_users
from gestor_inventory.application.manage_users import (
    DeleteUserRequest,
    delete_user,
    GetUserRequest,
    get_user,
    UpdateUserRequest,
    update_user,
)
from gestor_inventory.application.list_categories import ListCategoriesRequest, list_categories
from gestor_inventory.application.list_products import ListProductsRequest, list_products
from gestor_inventory.application.create_product import CreateProductRequest, create_product
from gestor_inventory.application.create_supplier import CreateSupplierRequest, create_supplier
from gestor_inventory.application.create_purchase_order import CreatePurchaseOrderRequest, create_purchase_order
from gestor_inventory.application.list_companies import ListCompaniesRequest, list_companies
from gestor_inventory.application.list_suppliers import ListSuppliersRequest, list_suppliers
from gestor_inventory.application.update_supplier import UpdateSupplierRequest, update_supplier
from gestor_inventory.application.deactivate_supplier import DeactivateSupplierRequest, deactivate_supplier
from gestor_inventory.application.manage_user_roles import (
    AssignUserRoleRequest,
    RevokeUserRoleRequest,
    assign_user_role,
    revoke_user_role,
)
from gestor_inventory.application.request_password_reset import RequestPasswordResetRequest, request_password_reset
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.application.reset_password import ResetPasswordRequest, reset_password
from gestor_inventory.application.update_branch import UpdateBranchRequest, update_branch
from gestor_inventory.application.update_company_setting import UpdateCompanySettingsRequest, update_company_settings
from gestor_inventory.application.update_product import UpdateProductRequest, update_product
from gestor_inventory.application.verify_email import VerifyEmailRequest, verify_email
from gestor_inventory.domain.errors import (
    AccountNotVerifiedError,
    BranchHasInventoryError,
    CompanyNameAlreadyExistsError,
    DuplicateBarcodeError,
    DuplicateSKUError,
    EmailAlreadyExistsError,
    ForbiddenError,
    InvalidCategoryError,
    InvalidSupplierError,
    InvalidCredentialsError,
    NotFoundError,
    PasswordResetTokenExpiredError,
    PasswordResetTokenInvalidError,
    RefreshTokenInvalidError,
    SupplierNotFoundError,
    ValidationError,
)
from gestor_inventory.infrastructure.resend_email_sender import EmailDeliveryError, NoopVerificationEmailSender
from gestor_inventory.security.jwt import verify_jwt_hs256


class HttpApiHandler(BaseHTTPRequestHandler):
    repo = None
    jwt_secret = None
    jwt_expiration_minutes = 60
    refresh_token_expiration_minutes = 10080
    email_sender = NoopVerificationEmailSender()
    public_base_url = None

    def end_headers(self):
        origin = self.headers.get("Origin")
        if origin == "http://127.0.0.1:5500":
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT.value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _preprocess_tenant(self) -> bool:
        tenant_header = self.headers.get("X-Tenant-ID")
        self.tenant_id = None
        if tenant_header is not None:
            try:
                tenant_id = int(tenant_header)
                if tenant_id <= 0:
                    raise ValueError()
            except (ValueError, TypeError):
                self._send_error(HTTPStatus.BAD_REQUEST, "Inquilino inválido")
                return False

            if not self.repo or not self.repo.company_is_active(company_id=tenant_id):
                self._send_error(HTTPStatus.FORBIDDEN, "Inquilino no encontrado o inactivo")
                return False

            self.tenant_id = tenant_id
        return True

    def _handle_get_public_branding(self) -> None:
        if self.tenant_id is None:
            self._send_error(HTTPStatus.BAD_REQUEST, "Se requiere la cabecera X-Tenant-ID")
            return
        try:
            res = get_company_settings(self.repo, GetCompanySettingsRequest(company_id=self.tenant_id))
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(
            HTTPStatus.OK,
            {"data": [{"key": s.setting_key, "value": s.setting_value} for s in res.settings]},
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/uploads/"):
            self._handle_serve_uploaded_file(parsed.path)
            return

        if not self._preprocess_tenant():
            return
        if parsed.path == "/api/companies/branding":
            self._handle_get_public_branding()
            return
        if parsed.path == "/api/auth/me":
            self._handle_me()
            return
        if parsed.path == "/api/users":
            self._handle_list_users(parsed.query)
            return
        if parsed.path.startswith("/api/users/"):
            self._handle_get_user(parsed.path)
            return
        if parsed.path == "/api/auth/verify":
            self._handle_verify_email(parsed.query)
            return
        if parsed.path in ("/api/dashboard", "/api/dashboard/summary"):
            self._handle_dashboard_summary(parsed.query)
            return
        if parsed.path in ("/api/alerts", "/api/dashboard/alerts"):
            self._handle_dashboard_alerts(parsed.query)
            return
        if parsed.path in ("/api/dashboard/movimientos-ultimos-7-dias", "/api/dashboard/chart"):
            self._handle_dashboard_chart(parsed.query)
            return
        if parsed.path in (
            "/api/inventory/movements",
            "/api/movements",
            "/api/movimientos",
            "/api/dashboard/movimientos-recientes",
        ):
            self._handle_list_inventory_movements(parsed.query)
            return
        if parsed.path == "/api/products":
            self._handle_list_products(parsed.query)
            return
        if parsed.path == "/api/auth/verify-email":
            self._handle_verify_email(parsed.query)
            return
        if parsed.path == "/api/inventory":
            self._handle_list_inventory(parsed.query)
            return
        if parsed.path == "/api/admin/companies":
            self._handle_list_companies(parsed.query)
            return
        if parsed.path == "/api/admin/branches":
            self._handle_list_branches(parsed.query)
            return
        if parsed.path == "/api/admin/suppliers":
            self._handle_list_suppliers(parsed.query)
            return
        if parsed.path == "/api/admin/products":
            self._handle_list_products(parsed.query)
            return
        if parsed.path == "/api/admin/categories":
            self._handle_list_categories(parsed.query)
            return
        if parsed.path == "/api/admin/settings":
            self._handle_get_company_settings()
            return
        if parsed.path == "/api/admin/roles":
            self._handle_list_roles()
            return
        if parsed.path == "/api/admin/permissions":
            self._handle_list_permissions()
            return
        if parsed.path == "/api/sat/regimenes":
            self._handle_list_sat_regimenes(parsed.query)
            return
        if parsed.path == "/api/sat/unidades":
            self._handle_list_sat_unidades(parsed.query)
            return
        if parsed.path == "/api/sat/productos":
            self._handle_list_sat_productos(parsed.query)
            return
        if parsed.path.startswith("/api/admin/categories/"):
            self._handle_get_category(parsed.path)
            return
        if parsed.path.startswith("/api/admin/"):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return
        self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")

    def _handle_list_branches(self, query: str) -> None:
        try:
            authz = self._require_permissions({"sucursales:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            city = (params.get("city") or [None])[0]
            status = (params.get("status") or [None])[0]
            res = list_branches(self.repo, ListBranchesRequest(company_id=company_id, city=city, status=status))
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="READ",
            resource="sucursales",
            details=json.dumps({"returned": len(res.branches)}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "data": [
                    {
                        "company_id": b.company_id,
                        "id": b.id,
                        "name": b.name,
                        "address": b.address,
                        "city": b.city,
                        "country": b.country,
                        "status": b.status,
                    }
                    for b in res.branches
                ]
            },
        )

    def _handle_list_suppliers(self, query: str) -> None:
        try:
            authz = self._require_permissions({"proveedores:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            name = (params.get("name") or [None])[0]
            document_id = (params.get("document_id") or [None])[0]
            status_raw = (params.get("status") or [None])[0]
            page_raw = (params.get("page") or ["1"])[0]
            per_page_raw = (params.get("per_page") or ["50"])[0]
            page = int(page_raw)
            per_page = int(per_page_raw)
            status = "active" if status_raw is None else status_raw
            if isinstance(status, str) and status.strip().lower() in ("", "all", "todas", "any"):
                status = None
            res = list_suppliers(
                self.repo,
                ListSuppliersRequest(
                    company_id=company_id,
                    name=name,
                    document_id=document_id,
                    status=status,
                    page=page,
                    per_page=per_page,
                ),
            )
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="READ",
            resource="proveedores",
            details=json.dumps(
                {"returned": len(res.suppliers), "page": res.page, "per_page": res.per_page},
                separators=(",", ":"),
            ),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "data": [
                    {
                        "company_id": s.company_id,
                        "id": s.id,
                        "name": s.name,
                        "document_id": s.document_id,
                        "contact_email": s.contact_email,
                        "phone": s.phone,
                        "status": s.status,
                        "created_at": s.created_at,
                        "updated_at": s.updated_at,
                    }
                    for s in res.suppliers
                ],
                "pagination": {
                    "total": res.total,
                    "page": res.page,
                    "per_page": res.per_page,
                    "pages": res.pages,
                },
            },
        )

    def _handle_list_products(self, query: str) -> None:
        try:
            authz = self._require_permissions({"productos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            category_id_raw = (params.get("category_id") or [None])[0]
            status_raw = (params.get("status") or [None])[0]
            search_raw = (params.get("q") or params.get("search") or [None])[0]
            page_raw = (params.get("page") or ["1"])[0]
            per_page_raw = (params.get("per_page") or ["50"])[0]
            page = int(page_raw)
            per_page = int(per_page_raw)
            category_id = None if category_id_raw in (None, "") else int(category_id_raw)
            status = "active" if status_raw is None else status_raw
            if isinstance(status, str) and status.strip().lower() in ("", "all", "todas", "any"):
                status = None
            res = list_products(
                self.repo,
                ListProductsRequest(
                    company_id=company_id,
                    category_id=category_id,
                    status=status,
                    search=search_raw,
                    page=page,
                    per_page=per_page,
                ),
            )
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="READ",
            resource="productos",
            details=json.dumps(
                {
                    "returned": len(res.products),
                    "page": res.page,
                    "per_page": res.per_page,
                    "category_id": category_id,
                    "status": status,
                },
                separators=(",", ":"),
            ),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "data": [
                    {
                        "company_id": p.company_id,
                        "id": p.id,
                        "category_id": p.category_id,
                        "sku": p.sku,
                        "barcode": p.barcode,
                        "name": p.name,
                        "description": p.description,
                        "stock_minimum": p.stock_minimum,
                        "status": p.status,
                        "is_active": p.is_active,
                        "created_at": p.created_at,
                        "updated_at": p.updated_at,
                    }
                    for p in res.products
                ],
                "meta": {"total": res.total, "page": res.page, "per_page": res.per_page, "pages": res.pages},
            },
        )

    def _handle_list_categories(self, query: str) -> None:
        try:
            authz = self._require_permissions({"categorias:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            status_raw = (params.get("status") or [None])[0]
            status = "active" if status_raw is None else status_raw
            if isinstance(status, str) and status.strip().lower() in ("", "all", "todas", "any"):
                status = None
            res = list_categories(self.repo, ListCategoriesRequest(company_id=company_id, status=status))
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="READ",
            resource="categorias",
            details=json.dumps({"returned": len(res.categories), "status": status}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "data": [
                    {
                        "company_id": c.company_id,
                        "id": c.id,
                        "name": c.name,
                        "description": c.description,
                        "status": c.status,
                        "is_active": c.is_active,
                    }
                    for c in res.categories
                ]
            },
        )

    def _handle_list_companies(self, query: str) -> None:
        try:
            authz = self._require_permissions({"empresas:leer"})
            if authz is None:
                return
            params = parse_qs(query, keep_blank_values=True)
            page_raw = (params.get("page") or ["1"])[0]
            per_page_raw = (params.get("per_page") or ["10"])[0]
            page = int(page_raw)
            per_page = int(per_page_raw)
            res = list_companies(self.repo, ListCompaniesRequest(page=page, per_page=per_page))
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="READ",
            resource="empresas",
            details=json.dumps({"page": res.page, "per_page": res.per_page, "returned": len(res.companies)}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "data": [
                    {
                        "id": c.id,
                        "name": c.name,
                        "currency": c.currency,
                        "timezone": c.timezone,
                        "status": c.status,
                        "created_at": str(c.created_at),
                    }
                    for c in res.companies
                ],
                "pagination": {"total": res.total, "page": res.page, "per_page": res.per_page, "pages": res.pages},
            },
        )

    def do_POST(self):
        if not self._preprocess_tenant():
            return
        if self.path == "/api/users/register":
            self._handle_register()
            return
        if self.path == "/api/users":
            self._handle_create_internal_user()
            return
        if self.path == "/api/auth/login":
            self._handle_login()
            return
        if self.path == "/api/auth/resend-verification":
            self._handle_resend_verification()
            return
        if self.path == "/api/auth/refresh":
            self._handle_refresh()
            return
        if self.path == "/api/auth/logout":
            self._handle_logout()
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
        if self.path == "/api/admin/branches":
            self._handle_create_branch()
            return
        if self.path == "/api/admin/users":
            self._handle_create_internal_user()
            return
        if self.path == "/api/admin/categories":
            self._handle_create_category()
            return
        if self.path == "/api/admin/products":
            self._handle_create_product()
            return
        if self.path == "/api/admin/suppliers":
            self._handle_create_supplier()
            return
        if self.path == "/api/admin/purchase-orders":
            self._handle_create_purchase_order()
            return
        if self.path == "/api/auth/password-reset/request":
            self._handle_password_reset_request()
            return
        if self.path == "/api/auth/password-reset/confirm":
            self._handle_password_reset_confirm()
            return
        if self.path.startswith("/api/admin/"):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return
        self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")

    def do_PUT(self):
        if not self._preprocess_tenant():
            return
        if self.path.startswith("/api/users/"):
            self._handle_update_user(self.path)
            return
        if self.path == "/api/admin/settings":
            self._handle_update_company_settings()
            return
        if self.path.startswith("/api/admin/branches/"):
            self._handle_update_branch(self.path)
            return
        if self.path.startswith("/api/admin/products/"):
            self._handle_update_product(self.path)
            return
        if self.path.startswith("/api/admin/suppliers/"):
            self._handle_update_supplier(self.path)
            return
        if self.path.startswith("/api/admin/"):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return
        self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")

    def do_DELETE(self):
        if not self._preprocess_tenant():
            return
        if self.path.startswith("/api/users/"):
            self._handle_delete_user(self.path)
            return
        if self.path.startswith("/api/admin/branches/"):
            self._handle_deactivate_branch(self.path)
            return
        if self.path.startswith("/api/admin/suppliers/"):
            self._handle_deactivate_supplier(self.path)
            return
        if self.path.startswith("/api/admin/"):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return
        self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")

    def do_PATCH(self):
        if not self._preprocess_tenant():
            return
        if self.path.startswith("/api/users/"):
            self._handle_update_user(self.path)
            return
        if self.path == "/api/admin/companies/default-branch":
            self._handle_set_company_default_branch()
            return
        if self.path.startswith("/api/admin/"):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return
        self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")

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
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except CompanyNameAlreadyExistsError:
            self._send_error(HTTPStatus.CONFLICT, "El nombre de la empresa ya existe")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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

    def _handle_set_company_default_branch(self) -> None:
        try:
            authz = self._require_permissions({"empresas:editar"})
            if authz is None:
                return
            payload = self._read_json()
            company_id = int(authz.get("company_id"))
            raw_id = payload.get("default_branch_id")
            default_branch_id = int(raw_id) if raw_id is not None else None
            set_company_default_branch(
                self.repo,
                SetCompanyDefaultBranchRequest(company_id=company_id, default_branch_id=default_branch_id),
            )
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="UPDATE",
            resource="empresas",
            details=json.dumps({"default_branch_id": default_branch_id}, separators=(",", ":")),
        )
        self._send_json(HTTPStatus.OK, {"status": "ok", "default_branch_id": default_branch_id})

    def _handle_get_company_settings(self) -> None:
        try:
            authz = self._require_permissions({"configuracion:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            res = get_company_settings(self.repo, GetCompanySettingsRequest(company_id=company_id))
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(
            HTTPStatus.OK,
            {"data": [{"key": s.setting_key, "value": s.setting_value} for s in res.settings]},
        )

    def _handle_update_company_settings(self) -> None:
        try:
            authz = self._require_permissions({"configuracion:editar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))

            content_type = self.headers.get("Content-Type", "")
            if content_type.startswith("multipart/form-data"):
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        "REQUEST_METHOD": self.command,
                        "CONTENT_TYPE": content_type,
                    }
                )
                
                settings_payload = {}
                for key in form.keys():
                    if key == "logo":
                        continue
                    val = form.getfirst(key)
                    if val is not None:
                        settings_payload[key] = val

                logo_url = None
                logo_item = form["logo"] if "logo" in form else None
                if isinstance(logo_item, list):
                    logo_item = logo_item[0]

                if logo_item is not None and hasattr(logo_item, "file") and logo_item.filename:
                    logo_data = logo_item.file.read()
                    logo_content_type = logo_item.type
                    
                    if logo_data:
                        if len(logo_data) > 2 * 1024 * 1024:
                            raise ValidationError("El archivo de logo no debe exceder los 2 MB")
                        
                        if logo_content_type not in ("image/png", "image/jpeg", "image/jpg"):
                            raise ValidationError("El formato del logo debe ser PNG o JPEG")
                        
                        is_png = logo_data.startswith(b'\x89PNG\r\n\x1a\n')
                        is_jpeg = logo_data.startswith(b'\xff\xd8')
                        if not (is_png or is_jpeg):
                            raise ValidationError("El archivo no es una imagen PNG o JPEG válida")
                        
                        width, height = None, None
                        if is_png:
                            try:
                                width, height = struct.unpack('>II', logo_data[16:24])
                            except Exception:
                                raise ValidationError("Error al leer las dimensiones de la imagen PNG")
                        elif is_jpeg:
                            try:
                                width_height = _get_jpeg_size(logo_data)
                                if width_height:
                                    width, height = width_height
                            except Exception:
                                raise ValidationError("Error al leer las dimensiones de la imagen JPEG")
                        
                        if width is not None and height is not None:
                            if width > 500 or height > 500:
                                raise ValidationError("Las dimensiones de la imagen no deben exceder 500x500 píxeles")

                        uploads_dir = os.environ.get("GI_UPLOADS_DIR", "uploads")
                        logos_dir = os.path.join(uploads_dir, "logos")
                        os.makedirs(logos_dir, exist_ok=True)
                        
                        ext = ".png" if is_png else ".jpg"
                        filename = f"{company_id}{ext}"
                        logo_filepath = os.path.join(logos_dir, filename)
                        
                        with open(logo_filepath, "wb") as f:
                            f.write(logo_data)
                        
                        base_url = self._resolve_base_url()
                        logo_url = f"{base_url}/uploads/logos/{filename}"
                        settings_payload["logo_url"] = logo_url
            else:
                payload = self._read_json()
                settings_payload = payload.get("settings") if isinstance(payload, dict) and "settings" in payload else payload

            update_company_settings(
                self.repo,
                UpdateCompanySettingsRequest(company_id=company_id, settings=settings_payload),
            )
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="UPDATE",
            resource="configuracion",
            details=json.dumps({"keys": sorted(list(settings_payload.keys()))}, ensure_ascii=False, separators=(",", ":")),
        )
        self._send_json(HTTPStatus.OK, {"status": "ok"})

    def _handle_create_branch(self) -> None:
        try:
            payload = self._read_json()
            authz = self._require_permissions({"sucursal:crear"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            res = create_branch(
                self.repo,
                CreateBranchRequest(
                    company_id=company_id,
                    name=payload["name"],
                    address=payload.get("address"),
                    city=payload.get("city"),
                    country=payload.get("country"),
                ),
            )
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        b = res.branch
        self._audit_data(
            authz,
            action="CREATE",
            resource="sucursales",
            details=json.dumps({"branch_id": b.id, "name": b.name}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {
                "branch_id": b.id,
                "branch": {
                    "company_id": b.company_id,
                    "id": b.id,
                    "name": b.name,
                    "address": b.address,
                    "city": b.city,
                    "country": b.country,
                    "status": b.status,
                    "is_active": b.is_active,
                }
            },
        )

    def _handle_create_internal_user(self) -> None:
        try:
            authz = self._require_permissions({"usuarios:crear"})
            if authz is None:
                return
            payload = self._read_json()
            company_id = int(authz.get("company_id"))
            actor_user_id = int(authz.get("sub"))
            req = CreateInternalUserRequest(
                company_id=company_id,
                actor_user_id=actor_user_id,
                email=payload["email"],
                password=payload["password"],
                role_id=int(payload["role_id"]),
            )
            base_url = self._resolve_base_url()
            res = create_internal_user(self.repo, req, base_url=base_url)
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ForbiddenError as e:
            self._send_error(HTTPStatus.FORBIDDEN, str(e) or "Prohibido")
            return
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except EmailAlreadyExistsError:
            self._send_error(HTTPStatus.CONFLICT, "El correo electrónico ya existe")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        email_sent = self._try_send_verification_email(res.user.email, res.verification_url)

        self._audit_data(
            authz,
            action="CREATE",
            resource="usuarios",
            details=json.dumps({"user_id": res.user.id, "role_id": res.role_id, "email": res.user.email}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {
                "user": {
                    "id": res.user.id,
                    "company_id": res.user.company_id,
                    "email": res.user.email,
                    "is_active": res.user.is_active,
                    "verified": res.user.verified,
                    "role_id": res.role_id,
                },
                "verification_url": res.verification_url,
                "verification_email_sent": email_sent,
            },
        )

    def _handle_update_user(self, path: str) -> None:
        try:
            authz = self._require_permissions({"usuarios:editar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            actor_user_id = int(authz.get("sub"))
            user_id = self._parse_user_id_from_path(path)
            payload = self._read_json()
            self._assert_mutable_user_payload(payload)
            res = update_user(
                self.repo,
                UpdateUserRequest(
                    company_id=company_id,
                    actor_user_id=actor_user_id,
                    user_id=user_id,
                    email=payload.get("email"),
                    password=payload.get("password"),
                    is_active=payload.get("is_active"),
                    verified=payload.get("verified"),
                ),
            )
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ForbiddenError as e:
            self._send_error(HTTPStatus.FORBIDDEN, str(e) or "Prohibido")
            return
        except EmailAlreadyExistsError:
            self._send_error(HTTPStatus.CONFLICT, "El correo electrónico ya existe")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="UPDATE",
            resource="usuarios",
            details=json.dumps({"user_id": res.user.id}, separators=(",", ":")),
        )
        self._send_json(HTTPStatus.OK, {"user": self._serialize_user(res.user)})

    def _handle_delete_user(self, path: str) -> None:
        try:
            authz = self._require_permissions({"usuarios:eliminar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            actor_user_id = int(authz.get("sub"))
            user_id = self._parse_user_id_from_path(path)
            res = delete_user(
                self.repo,
                DeleteUserRequest(company_id=company_id, actor_user_id=actor_user_id, user_id=user_id),
            )
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ForbiddenError as e:
            self._send_error(HTTPStatus.FORBIDDEN, str(e) or "Prohibido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="DELETE",
            resource="usuarios",
            details=json.dumps({"user_id": int(user_id), "changed": bool(res.changed)}, separators=(",", ":")),
        )
        self._send_json(HTTPStatus.OK, {"status": "ok", "changed": res.changed})

    def _handle_update_branch(self, path: str) -> None:
        try:
            authz = self._require_permissions({"sucursales:editar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            raw_id = path.removeprefix("/api/admin/branches/").strip("/")
            branch_id = int(raw_id)
            payload = self._read_json()
            res = update_branch(
                self.repo,
                UpdateBranchRequest(
                    company_id=company_id,
                    branch_id=branch_id,
                    name=payload.get("name"),
                    address=payload.get("address"),
                    city=payload.get("city"),
                    country=payload.get("country"),
                ),
            )
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        b = res.branch
        self._audit_data(
            authz,
            action="UPDATE",
            resource="sucursales",
            details=json.dumps({"branch_id": b.id}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "branch": {
                    "company_id": b.company_id,
                    "id": b.id,
                    "name": b.name,
                    "address": b.address,
                    "city": b.city,
                    "country": b.country,
                    "status": b.status,
                    "is_active": b.is_active,
                }
            },
        )

    def _handle_update_product(self, path: str) -> None:
        try:
            authz = self._require_permissions({"productos:editar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            raw_id = path.removeprefix("/api/admin/products/").strip("/")
            product_id = int(raw_id)
            payload = self._read_json()
            if "company_id" in payload:
                raise ValidationError("company_id es inmutable")
            res = update_product(
                self.repo,
                UpdateProductRequest(
                    company_id=company_id,
                    product_id=product_id,
                    name=payload.get("name"),
                    sku=payload.get("sku"),
                    barcode=payload.get("barcode"),
                    category_id=payload.get("category_id"),
                    description=payload.get("description"),
                    stock_minimum=payload.get("stock_minimum"),
                    status=payload.get("status"),
                ),
            )
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except DuplicateSKUError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Ya existe un producto registrado con este SKU o código en tu empresa. Por favor, utiliza uno diferente.",
            )
            return
        except DuplicateBarcodeError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Este código alterno ya está registrado.",
            )
            return
        except InvalidCategoryError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "La categoría no pertenece a esta empresa",
            )
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        p = res.product
        self._audit_data(
            authz,
            action="UPDATE",
            resource="productos",
            details=json.dumps({"product_id": p.id}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "product": {
                    "company_id": p.company_id,
                    "id": p.id,
                    "category_id": p.category_id,
                    "sku": p.sku,
                    "barcode": p.barcode,
                    "name": p.name,
                    "description": p.description,
                    "stock_minimum": p.stock_minimum,
                    "status": p.status,
                    "is_active": p.is_active,
                    "created_at": p.created_at,
                    "updated_at": p.updated_at,
                }
            },
        )

    def _handle_update_supplier(self, path: str) -> None:
        try:
            authz = self._require_permissions({"proveedores:editar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            raw_id = path.removeprefix("/api/admin/suppliers/").strip("/")
            supplier_id = int(raw_id)
            payload = self._read_json()
            if "company_id" in payload:
                raise ValidationError("company_id es inmutable")
            res = update_supplier(
                self.repo,
                UpdateSupplierRequest(
                    company_id=company_id,
                    supplier_id=supplier_id,
                    name=payload.get("name"),
                    contact_email=payload.get("contact_email"),
                    phone=payload.get("phone"),
                    status=payload.get("status"),
                ),
            )
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        s = res.supplier
        self._audit_data(
            authz,
            action="UPDATE",
            resource="proveedores",
            details=json.dumps({"supplier_id": s.id}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "supplier": {
                    "company_id": s.company_id,
                    "id": s.id,
                    "name": s.name,
                    "document_id": s.document_id,
                    "contact_email": s.contact_email,
                    "phone": s.phone,
                    "status": s.status,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                }
            },
        )

    def _handle_deactivate_branch(self, path: str) -> None:
        try:
            authz = self._require_permissions({"sucursales:eliminar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            raw_id = path.removeprefix("/api/admin/branches/").strip("/")
            branch_id = int(raw_id)
            res = deactivate_branch(self.repo, DeactivateBranchRequest(company_id=company_id, branch_id=branch_id))
        except BranchHasInventoryError:
            self._send_error(HTTPStatus.CONFLICT, "La sucursal tiene inventario")
            return
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="DELETE",
            resource="sucursales",
            details=json.dumps({"branch_id": int(branch_id), "changed": bool(res.changed)}, separators=(",", ":")),
        )
        self._send_json(HTTPStatus.OK, {"status": "ok", "changed": res.changed})

    def _handle_deactivate_supplier(self, path: str) -> None:
        try:
            authz = self._require_permissions({"proveedores:eliminar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            raw_id = path.removeprefix("/api/admin/suppliers/").strip("/")
            supplier_id = int(raw_id)
            res = deactivate_supplier(
                self.repo, DeactivateSupplierRequest(company_id=company_id, supplier_id=supplier_id)
            )
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="DELETE",
            resource="proveedores",
            details=json.dumps({"supplier_id": int(supplier_id), "changed": bool(res.changed)}, separators=(",", ":")),
        )
        self._send_json(HTTPStatus.OK, {"status": "ok", "changed": res.changed})

    def _handle_register(self) -> None:
        try:
            payload = self._read_json()
            if self.tenant_id is not None:
                payload_company_id = payload.get("company_id")
                if payload_company_id is not None:
                    try:
                        if int(payload_company_id) != self.tenant_id:
                            self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                            return
                    except (ValueError, TypeError):
                        self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                        return
            else:
                payload.pop("company_id", None)
                payload.pop("role_id", None)
            req = RegisterUserRequest(
                email=payload["email"],
                password=payload["password"],
                company_name=payload.get("company_name"),
                currency=payload.get("currency", "USD"),
                timezone=payload.get("timezone", "UTC"),
            )
            base_url = self._resolve_base_url()
            res = register_user(self.repo, req, base_url=base_url)
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except CompanyNameAlreadyExistsError:
            self._send_error(HTTPStatus.CONFLICT, "El nombre de la empresa ya existe")
            return
        except EmailAlreadyExistsError:
            self._send_error(HTTPStatus.CONFLICT, "El correo electrónico ya existe")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        email_sent = self._try_send_verification_email(res.user.email, res.verification_url)

        self._send_json(
            HTTPStatus.CREATED,
            {
                "id": res.user.id,
                "company_id": res.company.id,
                "company_name": res.company.name,
                "email": res.user.email,
                "is_active": res.user.is_active,
                "verified": res.user.verified,
                "role_id": res.role_id,
                "verification_url": res.verification_url,
                "verification_email_sent": email_sent,
            },
        )

    def _handle_login(self) -> None:
        try:
            payload = self._read_json()
            if self.tenant_id is not None:
                payload_company_id = payload.get("company_id")
                if payload_company_id is not None:
                    try:
                        if int(payload_company_id) != self.tenant_id:
                            self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                            return
                    except (ValueError, TypeError):
                        self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                        return
                else:
                    payload["company_id"] = self.tenant_id
            else:
                payload_company_id = payload.get("company_id")
                if payload_company_id is None:
                    email = payload.get("email")
                    if email:
                        if hasattr(self.repo, "find_company_id_by_email"):
                            resolved_id = self.repo.find_company_id_by_email(email=email)
                            if resolved_id is not None:
                                payload["company_id"] = resolved_id
                            else:
                                self._send_error(HTTPStatus.UNAUTHORIZED, "Credenciales inválidas")
                                return
                        else:
                            self._send_error(HTTPStatus.BAD_REQUEST, "Se requiere company_id")
                            return
                    else:
                        self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
                        return
            req = LoginRequest(
                company_id=payload["company_id"],
                email=payload["email"],
                password=payload["password"],
            )
            if not isinstance(self.jwt_secret, str) or not self.jwt_secret:
                self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
                return
            res = login_user(
                self.repo,
                req,
                jwt_secret=self.jwt_secret,
                access_token_ttl_seconds=int(self.jwt_expiration_minutes) * 60,
                refresh_token_ttl_seconds=int(self.refresh_token_expiration_minutes) * 60,
            )
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except AccountNotVerifiedError:
            self._send_error(
                HTTPStatus.FORBIDDEN,
                "Debes verificar tu cuenta antes de iniciar sesión",
            )
            return
        except (ValidationError, InvalidCredentialsError):
            self._send_error(HTTPStatus.UNAUTHORIZED, "Credenciales inválidas")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "access_token": res.access_token,
                "refresh_token": res.refresh_token,
                "token_type": "bearer",
                "settings": res.settings,
            },
        )

    def _handle_logout(self) -> None:
        try:
            payload = self._read_json()
            if self.tenant_id is not None:
                payload_company_id = payload.get("company_id")
                if payload_company_id is not None:
                    try:
                        if int(payload_company_id) != self.tenant_id:
                            self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                            return
                    except (ValueError, TypeError):
                        self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                        return
                else:
                    payload["company_id"] = self.tenant_id
            req = LogoutRequest(
                company_id=payload["company_id"],
                refresh_token=payload["refresh_token"],
            )
            logout_user(self.repo, req)
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except RefreshTokenInvalidError:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "Refresh token inválido o expirado",
            )
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(HTTPStatus.OK, {"status": "ok"})

    def _handle_resend_verification(self) -> None:
        try:
            payload = self._read_json()
            if self.tenant_id is not None:
                payload_company_id = payload.get("company_id")
                if payload_company_id is not None:
                    try:
                        if int(payload_company_id) != self.tenant_id:
                            self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                            return
                    except (ValueError, TypeError):
                        self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                        return
                else:
                    payload["company_id"] = self.tenant_id
            req = ResendVerificationEmailRequest(
                company_id=payload["company_id"],
                email=payload["email"],
            )
            res = resend_verification_email(
                self.repo,
                req,
                base_url=self._resolve_base_url(),
            )
            if not res.sent or not res.verification_url:
                self._send_json(HTTPStatus.OK, {"status": "ok", "sent": False})
                return
            self._send_verification_email(payload["email"], res.verification_url)
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except EmailDeliveryError as e:
            self._send_error(
                HTTPStatus.BAD_GATEWAY,
                str(e) or "No fue posible enviar el correo",
            )
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(HTTPStatus.OK, {"status": "ok", "sent": True})

    def _handle_refresh(self) -> None:
        try:
            payload = self._read_json()
            if self.tenant_id is not None:
                payload_company_id = payload.get("company_id")
                if payload_company_id is not None:
                    try:
                        if int(payload_company_id) != self.tenant_id:
                            self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                            return
                    except (ValueError, TypeError):
                        self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con el cuerpo de la petición")
                        return
                else:
                    payload["company_id"] = self.tenant_id
            req = RefreshAccessTokenRequest(
                company_id=payload["company_id"],
                refresh_token=payload["refresh_token"],
            )
            if not isinstance(self.jwt_secret, str) or not self.jwt_secret:
                self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
                return
            res = refresh_access_token(
                self.repo,
                req,
                jwt_secret=self.jwt_secret,
                access_token_ttl_seconds=int(self.jwt_expiration_minutes) * 60,
                refresh_token_ttl_seconds=int(self.refresh_token_expiration_minutes) * 60,
            )
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except RefreshTokenInvalidError:
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "Refresh token inválido o expirado",
            )
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "access_token": res.access_token,
                "refresh_token": res.refresh_token,
                "token_type": "bearer",
            },
        )

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

    def _handle_list_users(self, query: str) -> None:
        try:
            authz = self._require_permissions({"usuarios:listar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            page = int((params.get("page") or ["1"])[0])
            per_page = int((params.get("per_page") or ["20"])[0])
            res = list_users(
                self.repo,
                ListUsersRequest(company_id=company_id, page=page, per_page=per_page),
            )
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="READ",
            resource="usuarios",
            details=json.dumps(
                {"returned": len(res.users), "page": res.page, "per_page": res.per_page},
                separators=(",", ":"),
            ),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "data": [
                    {
                        "id": u.id,
                        "company_id": u.company_id,
                        "email": u.email,
                        "is_active": u.is_active,
                        "verified": u.verified,
                        "roles": u.roles,
                    }
                    for u in res.users
                ],
                "pagination": {
                    "total": res.total,
                    "page": res.page,
                    "per_page": res.per_page,
                    "pages": res.pages,
                },
            },
        )

    def _handle_get_user(self, path: str) -> None:
        try:
            authz = self._require_permissions({"usuarios:listar"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            user_id = self._parse_user_id_from_path(path)
            res = get_user(self.repo, GetUserRequest(company_id=company_id, user_id=user_id))
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._audit_data(
            authz,
            action="READ",
            resource="usuarios",
            details=json.dumps({"user_id": res.user.id}, separators=(",", ":")),
        )
        self._send_json(HTTPStatus.OK, {"user": self._serialize_user(res.user)})

    def _handle_verify_email(self, query: str) -> None:
        try:
            params = parse_qs(query, keep_blank_values=True)
            company_id_raw = (params.get("company_id") or [None])[0]
            if self.tenant_id is not None and company_id_raw is not None:
                try:
                    if int(company_id_raw) != self.tenant_id:
                        self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con los parámetros de consulta")
                        return
                except (ValueError, TypeError):
                    self._send_error(HTTPStatus.BAD_REQUEST, "El inquilino no coincide con los parámetros de consulta")
                    return
            token_raw = (params.get("token") or [None])[0]
            req = VerifyEmailRequest(
                company_id=(None if company_id_raw in (None, "") else int(company_id_raw)),
                token=token_raw,
            )
            verify_email(self.repo, req)
        except (TypeError, ValueError, KeyError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(HTTPStatus.OK, {"status": "ok"})

    def _handle_list_roles(self) -> None:
        try:
            authz = self._require_permissions({"roles:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            res = list_roles(self.repo, ListRolesRequest(company_id=company_id))
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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
            if branch_id_raw is None:
                token_branch_id = authz.get("branch_id")
                if token_branch_id is None:
                    raise ValueError("missing branch_id")
                branch_id = int(token_branch_id)
            else:
                branch_id = int(branch_id_raw)
            if not self._require_branch_access(authz, branch_id):
                return
            res = list_inventory(self.repo, ListInventoryRequest(company_id=company_id, branch_id=branch_id))
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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

    def _handle_list_inventory_movements(self, query: str) -> None:
        try:
            authz = self._require_permissions({"movimientos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            
            limit_raw = (params.get("limit") or [None])[0]
            limit = int(limit_raw) if limit_raw else 50

            branch_id_raw = (params.get("branch_id") or [None])[0]
            if branch_id_raw is None:
                token_branch_id = authz.get("branch_id")
                if token_branch_id is None:
                    branches = self.repo.list_branches(company_id=company_id, city=None, status="active")
                    if not branches:
                        raise ValueError("No active branch found")
                    branch_id = branches[0].id
                else:
                    branch_id = int(token_branch_id)
            else:
                branch_id = int(branch_id_raw)

            if not self._require_branch_access(authz, branch_id):
                return

            res = list_inventory_movements(
                self.repo,
                ListInventoryMovementsRequest(
                    company_id=company_id,
                    branch_id=branch_id,
                    limit=limit
                )
            )

            movements_data = []
            for m in res.movements:
                prod = self.repo.get_product_by_id(company_id=company_id, product_id=m.product_id)
                branch = self.repo.get_branch_by_id(company_id=company_id, branch_id=m.branch_id)
                user = self.repo.get_user_by_id(company_id=company_id, user_id=m.user_id)

                movements_data.append({
                    "id": m.id,
                    "fecha": time.strftime("%Y-%m-%d", time.localtime(m.created_at)),
                    "rawDate": time.strftime("%Y-%m-%d", time.localtime(m.created_at)),
                    "hora": time.strftime("%H:%M", time.localtime(m.created_at)),
                    "created_at": m.created_at * 1000,
                    "tipo": m.movement_type.capitalize(),
                    "type": m.movement_type,
                    "sku": prod.sku if prod else f"SKU-{m.product_id}",
                    "producto": prod.name if prod else "Sin producto",
                    "product": prod.name if prod else "Sin producto",
                    "cantidad": m.quantity,
                    "quantity": m.quantity,
                    "origen": branch.name if branch else "Sin origen",
                    "destino": branch.name if branch else "Sin destino",
                    "almacen": branch.name if branch else "Sin almacen",
                    "warehouse": branch.name if branch else "Sin almacen",
                    "usuario": user.email if user else "Sistema",
                    "user": user.email if user else "Sistema",
                })

            self._send_json(HTTPStatus.OK, movements_data)
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
        except Exception as e:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error interno: {str(e)}")

    def _handle_dashboard_summary(self, query: str) -> None:
        try:
            authz = self._require_permissions({"productos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            
            branch_id_raw = (params.get("branch_id") or [None])[0]
            if branch_id_raw is None:
                token_branch_id = authz.get("branch_id")
                if token_branch_id is None:
                    branches = self.repo.list_branches(company_id=company_id, city=None, status="active")
                    if not branches:
                        raise ValueError("No active branch found")
                    branch_id = branches[0].id
                else:
                    branch_id = int(token_branch_id)
            else:
                branch_id = int(branch_id_raw)

            if not self._require_branch_access(authz, branch_id):
                return

            products_res = list_products(
                self.repo,
                ListProductsRequest(
                    company_id=company_id,
                    category_id=None,
                    status="active",
                    search=None,
                    page=1,
                    per_page=10000
                )
            )
            total_products = len(products_res.products)

            branches = self.repo.list_branches(company_id=company_id, city=None, status="active")
            total_almacenes = len(branches)

            all_movements = self.repo.list_inventory_movements(company_id=company_id, branch_id=branch_id, limit=1000)
            current_date_str = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            today_start_epoch = int(time.mktime(time.strptime(current_date_str, "%Y-%m-%d")))
            movimientos_hoy = sum(1 for m in all_movements if m.created_at >= today_start_epoch)

            inventory_items = self.repo.list_inventory_items(company_id=company_id, branch_id=branch_id)
            alertas_stock = sum(1 for item in inventory_items if item.quantity <= item.min_quantity)

            self._send_json(
                HTTPStatus.OK,
                {
                    "productos": total_products,
                    "almacenes": total_almacenes,
                    "movimientos_hoy": movimientos_hoy,
                    "alertas_stock": alertas_stock
                }
            )
        except Exception as e:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error interno: {str(e)}")

    def _handle_dashboard_alerts(self, query: str) -> None:
        try:
            authz = self._require_permissions({"inventario:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            
            branch_id_raw = (params.get("branch_id") or [None])[0]
            if branch_id_raw is None:
                token_branch_id = authz.get("branch_id")
                if token_branch_id is None:
                    branches = self.repo.list_branches(company_id=company_id, city=None, status="active")
                    if not branches:
                        raise ValueError("No active branch found")
                    branch_id = branches[0].id
                else:
                    branch_id = int(token_branch_id)
            else:
                branch_id = int(branch_id_raw)

            if not self._require_branch_access(authz, branch_id):
                return

            inventory_items = self.repo.list_inventory_items(company_id=company_id, branch_id=branch_id)
            alerts = []
            
            for item in inventory_items:
                if item.quantity <= item.min_quantity:
                    prod = self.repo.get_product_by_id(company_id=company_id, product_id=item.product_id)
                    prod_name = prod.name if prod else f"Producto #{item.product_id}"
                    alerts.append({
                        "id": f"alert-{item.product_id}",
                        "title": prod_name,
                        "message": f"Stock bajo: {item.quantity} unidades (mínimo {item.min_quantity}).",
                        "time": time.strftime("%Y-%m-%d %H:%M", time.localtime(item.updated_at)),
                        "created_at": item.updated_at * 1000
                    })

            self._send_json(HTTPStatus.OK, {"data": alerts})
        except Exception as e:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error interno: {str(e)}")

    def _handle_dashboard_chart(self, query: str) -> None:
        try:
            authz = self._require_permissions({"movimientos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            params = parse_qs(query, keep_blank_values=True)
            
            branch_id_raw = (params.get("branch_id") or [None])[0]
            if branch_id_raw is None:
                token_branch_id = authz.get("branch_id")
                if token_branch_id is None:
                    branches = self.repo.list_branches(company_id=company_id, city=None, status="active")
                    if not branches:
                        raise ValueError("No active branch found")
                    branch_id = branches[0].id
                else:
                    branch_id = int(token_branch_id)
            else:
                branch_id = int(branch_id_raw)

            if not self._require_branch_access(authz, branch_id):
                return

            import datetime
            days_translation = {
                "Monday": "Lun",
                "Tuesday": "Mar",
                "Wednesday": "Mié",
                "Thursday": "Jue",
                "Friday": "Vie",
                "Saturday": "Sáb",
                "Sunday": "Dom"
            }
            
            today = datetime.date.today()
            chart_days = []
            for i in range(6, -1, -1):
                day_date = today - datetime.timedelta(days=i)
                date_str = day_date.strftime("%Y-%m-%d")
                day_name_en = day_date.strftime("%A")
                day_label = days_translation.get(day_name_en, day_name_en[:3])
                chart_days.append({
                    "date_str": date_str,
                    "label": day_label,
                    "value": 0
                })
                
            all_movements = self.repo.list_inventory_movements(company_id=company_id, branch_id=branch_id, limit=1000)
            
            for m in all_movements:
                m_date_str = time.strftime("%Y-%m-%d", time.localtime(m.created_at))
                for day in chart_days:
                    if day["date_str"] == m_date_str:
                        day["value"] += 1
                        break
                        
            chart_data = [{"label": d["label"], "value": d["value"]} for d in chart_days]
            self._send_json(HTTPStatus.OK, {"data": chart_data})
        except Exception as e:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error interno: {str(e)}")

    def _handle_get_category(self, path: str) -> None:
        try:
            authz = self._require_permissions({"productos:leer"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            raw_id = path.removeprefix("/api/admin/categories/").strip("/")
            category_id = int(raw_id)
            res = get_category(self.repo, GetCategoryRequest(company_id=company_id, category_id=category_id))
        except NotFoundError:
            self._send_error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        c = res.category
        self._send_json(
            HTTPStatus.OK,
            {"category": {"company_id": c.company_id, "id": c.id, "name": c.name, "is_active": c.is_active}},
        )

    def _parse_sat_catalog_request(self, query: str) -> ListSatCatalogRequest:
        params = parse_qs(query, keep_blank_values=True)
        search = (params.get("search") or params.get("q") or [None])[0]
        page_raw = (params.get("page") or ["1"])[0]
        per_page_raw = (params.get("per_page") or ["50"])[0]
        return ListSatCatalogRequest(search=search, page=int(page_raw), per_page=int(per_page_raw))

    def _handle_list_sat_regimenes(self, query: str) -> None:
        try:
            req = self._parse_sat_catalog_request(query)
            res = list_sat_regimenes_use_case(self.repo, req)
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "data": [self._serialize_sat_catalog_item(item) for item in res.items],
                "pagination": {
                    "total": res.total,
                    "page": res.page,
                    "per_page": res.per_page,
                    "pages": res.pages,
                },
            },
        )

    def _handle_list_sat_unidades(self, query: str) -> None:
        try:
            req = self._parse_sat_catalog_request(query)
            res = list_sat_unidades_use_case(self.repo, req)
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "data": [self._serialize_sat_catalog_item(item) for item in res.items],
                "pagination": {
                    "total": res.total,
                    "page": res.page,
                    "per_page": res.per_page,
                    "pages": res.pages,
                },
            },
        )

    def _handle_list_sat_productos(self, query: str) -> None:
        try:
            req = self._parse_sat_catalog_request(query)
            res = list_sat_productos_use_case(self.repo, req)
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "data": [self._serialize_sat_catalog_item(item) for item in res.items],
                "pagination": {
                    "total": res.total,
                    "page": res.page,
                    "per_page": res.per_page,
                    "pages": res.pages,
                },
            },
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
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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

    def _handle_create_product(self) -> None:
        try:
            payload = self._read_json()
            authz = self._require_permissions({"productos:crear"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            category_id_raw = payload["category_id"]
            res = create_product(
                self.repo,
                CreateProductRequest(
                    company_id=company_id,
                    sku=payload["sku"],
                    name=payload["name"],
                    category_id=int(category_id_raw),
                    barcode=payload.get("barcode"),
                    description=payload.get("description"),
                    stock_minimum=int(payload.get("stock_minimum", 0)),
                    status=str(payload.get("status", "active")),
                ),
            )
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except DuplicateSKUError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Ya existe un producto registrado con este SKU o código en tu empresa. Por favor, utiliza uno diferente.",
            )
            return
        except DuplicateBarcodeError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Este código alterno ya está registrado.",
            )
            return
        except InvalidCategoryError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "La categoría no pertenece a esta empresa",
            )
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        p = res.product
        self._audit_data(
            authz,
            action="CREATE",
            resource="productos",
            details=json.dumps({"product_id": p.id, "sku": p.sku, "category_id": p.category_id}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {
                "product": {
                    "company_id": p.company_id,
                    "id": p.id,
                    "category_id": p.category_id,
                    "sku": p.sku,
                    "barcode": p.barcode,
                    "name": p.name,
                    "description": p.description,
                    "stock_minimum": p.stock_minimum,
                    "status": p.status,
                    "is_active": p.is_active,
                    "created_at": p.created_at,
                    "updated_at": p.updated_at,
                }
            },
        )

    def _handle_create_supplier(self) -> None:
        try:
            payload = self._read_json()
            authz = self._require_permissions({"proveedores:crear"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            res = create_supplier(
                self.repo,
                CreateSupplierRequest(
                    company_id=company_id,
                    name=payload["name"],
                    document_id=payload.get("document_id"),
                    contact_email=payload.get("contact_email"),
                    phone=payload.get("phone"),
                ),
            )
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        s = res.supplier
        self._audit_data(
            authz,
            action="CREATE",
            resource="proveedores",
            details=json.dumps({"supplier_id": s.id}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {
                "supplier": {
                    "company_id": s.company_id,
                    "id": s.id,
                    "name": s.name,
                    "document_id": s.document_id,
                    "contact_email": s.contact_email,
                    "phone": s.phone,
                    "status": s.status,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                }
            },
        )

    def _handle_create_purchase_order(self) -> None:
        try:
            payload = self._read_json()
            authz = self._require_permissions({"compras:crear"})
            if authz is None:
                return
            company_id = int(authz.get("company_id"))
            supplier_id = int(payload["supplier_id"])
            res = create_purchase_order(
                self.repo,
                CreatePurchaseOrderRequest(company_id=company_id, supplier_id=supplier_id),
            )
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except SupplierNotFoundError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Proveedor no encontrado")
            return
        except InvalidSupplierError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Proveedor inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return

        po = res.purchase_order
        self._audit_data(
            authz,
            action="CREATE",
            resource="compras",
            details=json.dumps({"purchase_order_id": po.id, "supplier_id": po.supplier_id}, separators=(",", ":")),
        )
        self._send_json(
            HTTPStatus.CREATED,
            {
                "purchase_order": {
                    "company_id": po.company_id,
                    "id": po.id,
                    "supplier_id": po.supplier_id,
                    "status": po.status,
                    "created_at": po.created_at,
                    "updated_at": po.updated_at,
                }
            },
        )

    def _handle_password_reset_request(self) -> None:
        try:
            payload = self._read_json()
            req = RequestPasswordResetRequest(company_id=payload["company_id"], email=payload["email"])
            res = request_password_reset(self.repo, req)
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except PasswordResetTokenExpiredError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Token expirado")
            return
        except PasswordResetTokenInvalidError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Token inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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
                actor_user_id=int(authz.get("sub")),
                user_id=int(payload["user_id"]),
                role_id=int(payload["role_id"]),
            )
            res = assign_user_role(self.repo, req)
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ForbiddenError as e:
            self._send_error(HTTPStatus.FORBIDDEN, str(e) or "Prohibido")
            return
        except NotFoundError as e:
            self._send_error(HTTPStatus.NOT_FOUND, str(e))
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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
                actor_user_id=int(authz.get("sub")),
                user_id=int(payload["user_id"]),
                role_id=int(payload["role_id"]),
            )
            res = revoke_user_role(self.repo, req)
        except KeyError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except ForbiddenError as e:
            self._send_error(HTTPStatus.FORBIDDEN, str(e) or "Prohibido")
            return
        except NotFoundError as e:
            self._send_error(HTTPStatus.NOT_FOUND, str(e))
            return
        except ValidationError as e:
            self._send_error(HTTPStatus.BAD_REQUEST, str(e))
            return
        except (TypeError, ValueError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Payload inválido")
            return
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON inválido")
            return
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
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
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
            return None
        auth = self.headers.get("Authorization", "")
        if not isinstance(auth, str) or not auth.startswith("Bearer "):
            self._send_error(HTTPStatus.UNAUTHORIZED, "No autorizado")
            return None
        token = auth.removeprefix("Bearer ").strip()
        if not token:
            self._send_error(HTTPStatus.UNAUTHORIZED, "No autorizado")
            return None
        try:
            payload = verify_jwt_hs256(token, secret=self.jwt_secret)
        except Exception:
            self._send_error(HTTPStatus.UNAUTHORIZED, "No autorizado")
            return None

        if getattr(self, "tenant_id", None) is not None:
            token_company_id = payload.get("company_id")
            if token_company_id is not None:
                try:
                    if int(token_company_id) != self.tenant_id:
                        self._send_error(HTTPStatus.FORBIDDEN, "Acceso denegado: el inquilino no coincide con el token")
                        return None
                except (ValueError, TypeError):
                    self._send_error(HTTPStatus.FORBIDDEN, "Acceso denegado: el inquilino no coincide con el token")
                    return None
        return payload

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
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return None
        if company_id is not None and int(token_company_id) != int(company_id):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return None

        sub = payload.get("sub")
        try:
            actor_user_id = int(sub)
        except Exception:
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return None

        if not hasattr(self.repo, "list_user_permission_codes"):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return None

        permissions = set(self.repo.list_user_permission_codes(company_id=int(token_company_id), user_id=actor_user_id))
        if required_permissions and not required_permissions.issubset(permissions):
            self._send_error(HTTPStatus.FORBIDDEN, "Prohibido")
            return None

        return payload

    def _require_branch_access(self, authz_payload: dict, target_branch_id: int) -> bool:
        branch_claim = authz_payload.get("branch_id")
        if branch_claim is None:
            return True
        if isinstance(branch_claim, str) and branch_claim.strip().lower() in ("", "all", "todas", "any"):
            return True
        try:
            actor_branch_id = int(branch_claim)
        except Exception:
            self._send_error(HTTPStatus.FORBIDDEN, "Acceso denegado a esta sucursal")
            return False
        if actor_branch_id <= 0:
            return True
        if int(actor_branch_id) != int(target_branch_id):
            self._send_error(HTTPStatus.FORBIDDEN, "Acceso denegado a esta sucursal")
            return False
        return True

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

    def _parse_user_id_from_path(self, path: str) -> int:
        raw_id = path.removeprefix("/api/users/").strip("/")
        if not raw_id:
            raise ValueError("missing user id")
        return int(raw_id)

    def _assert_mutable_user_payload(self, payload: dict) -> None:
        for field in ("id", "company_id", "role_id", "roles"):
            if field in payload:
                raise ValidationError(f"{field} es inmutable")

    def _serialize_user(self, user) -> dict:
        return {
            "id": user.id,
            "company_id": user.company_id,
            "email": user.email,
            "is_active": user.is_active,
            "verified": user.verified,
            "roles": user.roles,
        }

    def _serialize_sat_catalog_item(self, item) -> dict:
        data = {"clave": item.clave}
        if hasattr(item, "descripcion"):
            data["descripcion"] = item.descripcion
        if hasattr(item, "nombre"):
            data["nombre"] = item.nombre
        if hasattr(item, "simbolo"):
            data["simbolo"] = item.simbolo
        if hasattr(item, "palabras_similares"):
            data["palabras_similares"] = item.palabras_similares
        return data

    def _resolve_base_url(self) -> str:
        configured = self.public_base_url
        if isinstance(configured, str) and configured.strip():
            return configured.strip().rstrip("/")
        host = self.headers.get("Host", "127.0.0.1")
        return f"http://{host}"

    def _send_verification_email(self, to_email: str, verification_url: str) -> None:
        sender = self.email_sender or NoopVerificationEmailSender()
        sender.send_verification_email(to_email=str(to_email), verification_url=str(verification_url))

    def _try_send_verification_email(self, to_email: str, verification_url: str) -> bool:
        try:
            self._send_verification_email(to_email, verification_url)
            return True
        except EmailDeliveryError:
            return False

    def _send_error(self, status: HTTPStatus, error_message: str) -> None:
        self._send_json(status, {"success": False, "error": error_message})

    def _send_json(self, status: HTTPStatus, body: dict) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle_serve_uploaded_file(self, path: str) -> None:
        suffix = path.removeprefix("/uploads/")
        suffix = os.path.normpath(suffix).lstrip(os.path.sep)
        
        uploads_dir = os.environ.get("GI_UPLOADS_DIR", "uploads")
        file_path = os.path.abspath(os.path.join(uploads_dir, suffix))
        
        abs_uploads_dir = os.path.abspath(uploads_dir)
        if not file_path.startswith(abs_uploads_dir) or not os.path.exists(file_path) or os.path.isdir(file_path):
            self._send_error(HTTPStatus.NOT_FOUND, "Archivo no encontrado")
            return
            
        content_type = "application/octet-stream"
        if file_path.lower().endswith(".png"):
            content_type = "image/png"
        elif file_path.lower().endswith((".jpg", ".jpeg")):
            content_type = "image/jpeg"
            
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            self.send_response(HTTPStatus.OK.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            
            origin = self.headers.get("Origin")
            if origin == "http://127.0.0.1:5500":
                self.send_header("Access-Control-Allow-Origin", origin)
            else:
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error al leer archivo")


def _get_jpeg_size(data: bytes) -> tuple[int, int] | None:
    size = len(data)
    i = 2
    while i + 4 < size:
        if data[i] != 0xFF:
            break
        marker = data[i+1]
        if marker == 0xD9:
            break
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if i + 9 <= size:
                height, width = struct.unpack('>HH', data[i+5:i+9])
                return width, height
            break
        else:
            segment_length = struct.unpack('>H', data[i+2:i+4])[0]
            i += 2 + segment_length
    return None
