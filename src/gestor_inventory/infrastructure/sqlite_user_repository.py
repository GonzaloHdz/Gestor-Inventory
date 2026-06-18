import sqlite3
from contextlib import contextmanager
import time

from gestor_inventory.domain.errors import EmailAlreadyExistsError
from gestor_inventory.domain.company import Company
from gestor_inventory.domain.operational import Branch, InventoryItem, InventoryMovement, Product
from gestor_inventory.domain.operational import Category
from gestor_inventory.domain.rbac import Permission, Role
from gestor_inventory.domain.user import User


class SqliteUserRepository:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._persistent_conn = sqlite3.connect(":memory:") if db_path == ":memory:" else None
        if self._persistent_conn is not None:
            self._persistent_conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def email_exists(self, *, company_id: int, email: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM users WHERE company_id = ? AND email = ? LIMIT 1",
                (company_id, email),
            ).fetchone()
            return row is not None

    def get_user_id_by_email(self, *, company_id: int, email: str) -> int | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE company_id = ? AND email = ? LIMIT 1",
                (company_id, email),
            ).fetchone()
            if row is None:
                return None
            (user_id,) = row
            return int(user_id)

    def create_user_with_role(
        self,
        *,
        company_id: int,
        email: str,
        password_hash: str,
        role_id: int,
    ) -> tuple[User, int]:
        with self._connect() as conn:
            try:
                conn.execute("BEGIN")
                self._ensure_base_rbac(conn, company_id=company_id)
                cur = conn.execute(
                    """
                    INSERT INTO users (company_id, email, password_hash, is_active, verified)
                    VALUES (?, ?, ?, 1, 0)
                    """,
                    (company_id, email, password_hash),
                )
                user_id = int(cur.lastrowid)
                conn.execute(
                    """
                    INSERT INTO user_roles (company_id, user_id, role_id)
                    VALUES (?, ?, ?)
                    """,
                    (company_id, user_id, role_id),
                )
                conn.execute("COMMIT")
            except sqlite3.IntegrityError as e:
                conn.execute("ROLLBACK")
                if "users.company_id" in str(e) or "users_company_email_unique" in str(e) or "users(company_id,email)" in str(e):
                    raise EmailAlreadyExistsError() from None
                raise

            user = User(
                id=user_id,
                company_id=company_id,
                email=email,
                password_hash=password_hash,
                is_active=True,
                verified=False,
            )
            return user, role_id

    def get_user_for_login(self, *, company_id: int, email: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, company_id, email, password_hash, is_active, verified
                FROM users
                WHERE company_id = ? AND email = ?
                LIMIT 1
                """,
                (company_id, email),
            ).fetchone()
            if row is None:
                return None
            user_id, company_id_v, email_v, password_hash, is_active, verified = row
            return {
                "id": int(user_id),
                "company_id": int(company_id_v),
                "email": str(email_v),
                "password_hash": str(password_hash),
                "is_active": bool(is_active),
                "verified": bool(verified),
            }

    def create_password_reset_token(
        self,
        *,
        company_id: int,
        user_id: int,
        token_hash: str,
        expires_at: int,
        created_at: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO password_reset_tokens (company_id, user_id, token_hash, expires_at, created_at, used_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (company_id, user_id, token_hash, int(expires_at), int(created_at)),
            )
            conn.commit()

    def create_email_verification_token(
        self,
        *,
        company_id: int,
        user_id: int,
        token_hash: str,
        expires_at: int,
        created_at: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO email_verification_tokens (company_id, user_id, token_hash, expires_at, created_at, used_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (company_id, user_id, str(token_hash), int(expires_at), int(created_at)),
            )
            conn.commit()

    def consume_email_verification_token_and_verify_user(
        self,
        *,
        company_id: int,
        token_hash: str,
        now: int,
    ) -> tuple[str, int | None]:
        with self._connect() as conn:
            conn.execute("BEGIN")
            row = conn.execute(
                """
                SELECT id, user_id, expires_at, used_at
                FROM email_verification_tokens
                WHERE company_id = ? AND token_hash = ?
                LIMIT 1
                """,
                (company_id, str(token_hash)),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return "not_found", None
            token_id, user_id, expires_at, used_at = row
            if used_at is not None:
                conn.execute("ROLLBACK")
                return "already_used", int(user_id)
            if int(now) > int(expires_at):
                conn.execute("ROLLBACK")
                return "expired", int(user_id)

            cur_user = conn.execute(
                """
                UPDATE users
                SET verified = 1
                WHERE company_id = ? AND id = ?
                """,
                (company_id, int(user_id)),
            )
            if cur_user.rowcount != 1:
                conn.execute("ROLLBACK")
                return "not_found", None

            cur_token = conn.execute(
                """
                UPDATE email_verification_tokens
                SET used_at = ?
                WHERE company_id = ? AND id = ? AND used_at IS NULL
                """,
                (int(now), company_id, int(token_id)),
            )
            if cur_token.rowcount != 1:
                conn.execute("ROLLBACK")
                return "already_used", int(user_id)

            conn.execute("COMMIT")
            return "ok", int(user_id)

    def get_password_reset_token(self, *, company_id: int, token_hash: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, company_id, user_id, token_hash, expires_at, created_at, used_at
                FROM password_reset_tokens
                WHERE company_id = ? AND token_hash = ?
                LIMIT 1
                """,
                (company_id, token_hash),
            ).fetchone()
            if row is None:
                return None
            token_id, company_id_v, user_id, token_hash_v, expires_at, created_at, used_at = row
            return {
                "id": int(token_id),
                "company_id": int(company_id_v),
                "user_id": int(user_id),
                "token_hash": str(token_hash_v),
                "expires_at": int(expires_at),
                "created_at": int(created_at),
                "used_at": int(used_at) if used_at is not None else None,
            }

    def consume_password_reset_token_and_update_password(
        self,
        *,
        company_id: int,
        token_hash: str,
        new_password_hash: str,
        now: int,
    ) -> tuple[str, int | None]:
        with self._connect() as conn:
            conn.execute("BEGIN")
            row = conn.execute(
                """
                SELECT id, user_id, expires_at, used_at
                FROM password_reset_tokens
                WHERE company_id = ? AND token_hash = ?
                LIMIT 1
                """,
                (company_id, token_hash),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return "not_found", None
            token_id, user_id, expires_at, used_at = row
            if used_at is not None:
                conn.execute("ROLLBACK")
                return "already_used", int(user_id)
            if int(now) > int(expires_at):
                conn.execute("ROLLBACK")
                return "expired", int(user_id)

            cur_user = conn.execute(
                """
                UPDATE users
                SET password_hash = ?
                WHERE company_id = ? AND id = ?
                """,
                (new_password_hash, company_id, int(user_id)),
            )
            if cur_user.rowcount != 1:
                conn.execute("ROLLBACK")
                return "not_found", None

            cur_token = conn.execute(
                """
                UPDATE password_reset_tokens
                SET used_at = ?
                WHERE company_id = ? AND id = ? AND used_at IS NULL
                """,
                (int(now), company_id, int(token_id)),
            )
            if cur_token.rowcount != 1:
                conn.execute("ROLLBACK")
                return "already_used", int(user_id)

            conn.execute("COMMIT")
            return "ok", int(user_id)

    def update_user_password_hash(self, *, company_id: int, user_id: int, password_hash: str) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE users
                SET password_hash = ?
                WHERE company_id = ? AND id = ?
                """,
                (password_hash, company_id, user_id),
            )
            if cur.rowcount != 1:
                raise sqlite3.IntegrityError("user not found")
            conn.commit()

    def user_belongs_to_company(self, *, company_id: int, user_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM users WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(user_id)),
            ).fetchone()
            return row is not None

    def role_belongs_to_company(self, *, company_id: int, role_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM roles WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(role_id)),
            ).fetchone()
            return row is not None

    def assign_role_to_user(self, *, company_id: int, user_id: int, role_id: int) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN")
            self._ensure_base_rbac(conn, company_id=int(company_id))
            row_user = conn.execute(
                "SELECT 1 FROM users WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(user_id)),
            ).fetchone()
            if row_user is None:
                conn.execute("ROLLBACK")
                return False
            row_role = conn.execute(
                "SELECT 1 FROM roles WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(role_id)),
            ).fetchone()
            if row_role is None:
                conn.execute("ROLLBACK")
                return False

            cur = conn.execute(
                """
                INSERT OR IGNORE INTO user_roles (company_id, user_id, role_id)
                VALUES (?, ?, ?)
                """,
                (int(company_id), int(user_id), int(role_id)),
            )
            conn.execute("COMMIT")
            return int(cur.rowcount) == 1

    def revoke_role_from_user(self, *, company_id: int, user_id: int, role_id: int) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN")
            row_user = conn.execute(
                "SELECT 1 FROM users WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(user_id)),
            ).fetchone()
            if row_user is None:
                conn.execute("ROLLBACK")
                return False
            row_role = conn.execute(
                "SELECT 1 FROM roles WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(role_id)),
            ).fetchone()
            if row_role is None:
                conn.execute("ROLLBACK")
                return False

            cur = conn.execute(
                """
                DELETE FROM user_roles
                WHERE company_id = ? AND user_id = ? AND role_id = ?
                """,
                (int(company_id), int(user_id), int(role_id)),
            )
            conn.execute("COMMIT")
            return int(cur.rowcount) >= 1

    def list_user_role_names(self, *, company_id: int, user_id: int) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT r.name
                FROM user_roles ur
                JOIN roles r ON r.company_id = ur.company_id AND r.id = ur.role_id
                WHERE ur.company_id = ? AND ur.user_id = ?
                ORDER BY r.id
                """,
                (int(company_id), int(user_id)),
            ).fetchall()
            return [str(name) for (name,) in rows]

    def list_user_permission_codes(self, *, company_id: int, user_id: int) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT p.code
                FROM user_roles ur
                JOIN role_permissions rp ON rp.company_id = ur.company_id AND rp.role_id = ur.role_id
                JOIN permissions p ON p.id = rp.permission_id
                WHERE ur.company_id = ? AND ur.user_id = ?
                ORDER BY p.code
                """,
                (int(company_id), int(user_id)),
            ).fetchall()
            return [str(code) for (code,) in rows]

    def get_role(self, *, company_id: int, role_id: int) -> Role | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, name, is_system
                FROM roles
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(role_id)),
            ).fetchone()
            if row is None:
                return None
            company_id_v, role_id_v, name, is_system = row
            return Role(
                company_id=int(company_id_v),
                id=int(role_id_v),
                name=str(name),
                is_system=bool(is_system),
            )

    def list_roles(self, *, company_id: int) -> list[Role]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT company_id, id, name, is_system
                FROM roles
                WHERE company_id = ?
                ORDER BY id
                """,
                (int(company_id),),
            ).fetchall()
            return [
                Role(
                    company_id=int(company_id_v),
                    id=int(role_id_v),
                    name=str(name),
                    is_system=bool(is_system),
                )
                for (company_id_v, role_id_v, name, is_system) in rows
            ]

    def get_permission_by_code(self, *, code: str) -> Permission | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, code, description
                FROM permissions
                WHERE code = ?
                LIMIT 1
                """,
                (str(code),),
            ).fetchone()
            if row is None:
                return None
            perm_id, code_v, description = row
            return Permission(id=int(perm_id), code=str(code_v), description=str(description) if description is not None else None)

    def list_permissions(self) -> list[Permission]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, code, description
                FROM permissions
                ORDER BY code
                """
            ).fetchall()
            return [
                Permission(id=int(perm_id), code=str(code_v), description=str(description) if description is not None else None)
                for (perm_id, code_v, description) in rows
            ]

    def create_category(self, *, company_id: int, name: str, is_active: bool) -> Category:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO categories (company_id, name, is_active)
                VALUES (?, ?, ?)
                """,
                (int(company_id), str(name), 1 if is_active else 0),
            )
            category_id = int(cur.lastrowid)
            conn.commit()
            return Category(company_id=int(company_id), id=category_id, name=str(name), is_active=bool(is_active))

    def get_category_by_id(self, *, company_id: int, category_id: int) -> Category | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, name, is_active
                FROM categories
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(category_id)),
            ).fetchone()
            if row is None:
                return None
            company_id_v, category_id_v, name, is_active = row
            return Category(company_id=int(company_id_v), id=int(category_id_v), name=str(name), is_active=bool(is_active))

    def create_branch(self, *, company_id: int, name: str, address: str | None, is_active: bool) -> Branch:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO branches (company_id, name, address, is_active)
                VALUES (?, ?, ?, ?)
                """,
                (int(company_id), str(name), str(address) if address is not None else None, 1 if is_active else 0),
            )
            branch_id = int(cur.lastrowid)
            conn.commit()
            return Branch(company_id=int(company_id), id=branch_id, name=str(name), address=address, is_active=bool(is_active))

    def branch_belongs_to_company(self, *, company_id: int, branch_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM branches WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(branch_id)),
            ).fetchone()
            return row is not None

    def create_product(
        self,
        *,
        company_id: int,
        category_id: int | None,
        sku: str,
        name: str,
        description: str | None,
        is_active: bool,
    ) -> Product:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO products (company_id, category_id, sku, name, description, is_active)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    int(company_id),
                    int(category_id) if category_id is not None else None,
                    str(sku),
                    str(name),
                    str(description) if description is not None else None,
                    1 if is_active else 0,
                ),
            )
            product_id = int(cur.lastrowid)
            conn.commit()
            return Product(
                company_id=int(company_id),
                id=product_id,
                category_id=int(category_id) if category_id is not None else None,
                sku=str(sku),
                name=str(name),
                description=description,
                is_active=bool(is_active),
            )

    def company_name_exists(self, *, name: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM companies WHERE name = ? LIMIT 1", (str(name),)).fetchone()
            return row is not None

    def create_company(self, *, name: str, currency: str, timezone: str, created_at: int) -> Company:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO companies (name, currency, timezone, status, created_at)
                VALUES (?, ?, ?, 'active', ?)
                """,
                (str(name), str(currency), str(timezone), int(created_at)),
            )
            company_id = int(cur.lastrowid)
            conn.commit()
            return Company(
                id=company_id,
                name=str(name),
                currency=str(currency),
                timezone=str(timezone),
                status="active",
                created_at=int(created_at),
            )

    def count_active_companies(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(1) FROM companies WHERE status = 'active'").fetchone()
            return 0 if row is None else int(row[0])

    def list_active_companies(self, *, limit: int, offset: int) -> list[Company]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, currency, timezone, status, created_at
                FROM companies
                WHERE status = 'active'
                ORDER BY id
                LIMIT ? OFFSET ?
                """,
                (int(limit), int(offset)),
            ).fetchall()
            return [
                Company(
                    id=int(company_id),
                    name=str(name),
                    currency=str(currency),
                    timezone=str(timezone),
                    status=str(status),
                    created_at=int(created_at),
                )
                for (company_id, name, currency, timezone, status, created_at) in rows
            ]

    def upsert_inventory_item(
        self,
        *,
        company_id: int,
        branch_id: int,
        product_id: int,
        quantity: int,
        min_quantity: int,
        updated_at: int | None = None,
    ) -> InventoryItem:
        with self._connect() as conn:
            now = int(time.time()) if updated_at is None else int(updated_at)
            conn.execute(
                """
                INSERT INTO inventory_items (company_id, branch_id, product_id, quantity, min_quantity, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(company_id, branch_id, product_id)
                DO UPDATE SET quantity = excluded.quantity, min_quantity = excluded.min_quantity, updated_at = excluded.updated_at
                """,
                (int(company_id), int(branch_id), int(product_id), int(quantity), int(min_quantity), int(now)),
            )
            conn.commit()
            return InventoryItem(
                company_id=int(company_id),
                branch_id=int(branch_id),
                product_id=int(product_id),
                quantity=int(quantity),
                min_quantity=int(min_quantity),
                updated_at=int(now),
            )

    def create_data_audit_log(
        self,
        *,
        company_id: int,
        user_id: int,
        action: str,
        resource: str,
        details: str | None,
        timestamp: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (company_id, user_id, action, resource, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    int(company_id),
                    int(user_id),
                    str(action),
                    str(resource),
                    str(details) if details is not None else None,
                    int(timestamp),
                ),
            )
            conn.commit()

    def list_inventory_items(self, *, company_id: int, branch_id: int) -> list[InventoryItem]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT company_id, branch_id, product_id, quantity, min_quantity, updated_at
                FROM inventory_items
                WHERE company_id = ? AND branch_id = ?
                ORDER BY product_id
                """,
                (int(company_id), int(branch_id)),
            ).fetchall()
            return [
                InventoryItem(
                    company_id=int(company_id_v),
                    branch_id=int(branch_id_v),
                    product_id=int(product_id),
                    quantity=int(quantity),
                    min_quantity=int(min_quantity),
                    updated_at=int(updated_at),
                )
                for (company_id_v, branch_id_v, product_id, quantity, min_quantity, updated_at) in rows
            ]

    def create_inventory_movement(
        self,
        *,
        company_id: int,
        branch_id: int,
        product_id: int,
        user_id: int,
        movement_type: str,
        quantity: int,
        reference: str | None,
        created_at: int | None = None,
    ) -> InventoryMovement:
        with self._connect() as conn:
            now = int(time.time()) if created_at is None else int(created_at)
            cur = conn.execute(
                """
                INSERT INTO inventory_movements (company_id, branch_id, product_id, user_id, movement_type, quantity, reference, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(company_id),
                    int(branch_id),
                    int(product_id),
                    int(user_id),
                    str(movement_type),
                    int(quantity),
                    str(reference) if reference is not None else None,
                    int(now),
                ),
            )
            movement_id = int(cur.lastrowid)
            conn.commit()
            return InventoryMovement(
                company_id=int(company_id),
                id=movement_id,
                branch_id=int(branch_id),
                product_id=int(product_id),
                user_id=int(user_id),
                movement_type=str(movement_type),
                quantity=int(quantity),
                reference=reference,
                created_at=int(now),
            )

    def list_inventory_movements(self, *, company_id: int, branch_id: int, limit: int) -> list[InventoryMovement]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT company_id, id, branch_id, product_id, user_id, movement_type, quantity, reference, created_at
                FROM inventory_movements
                WHERE company_id = ? AND branch_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (int(company_id), int(branch_id), int(limit)),
            ).fetchall()
            return [
                InventoryMovement(
                    company_id=int(company_id_v),
                    id=int(movement_id),
                    branch_id=int(branch_id_v),
                    product_id=int(product_id),
                    user_id=int(user_id),
                    movement_type=str(movement_type),
                    quantity=int(quantity),
                    reference=str(reference) if reference is not None else None,
                    created_at=int(created_at),
                )
                for (
                    company_id_v,
                    movement_id,
                    branch_id_v,
                    product_id,
                    user_id,
                    movement_type,
                    quantity,
                    reference,
                    created_at,
                ) in rows
            ]

    def create_audit_log(
        self,
        *,
        company_id: int,
        branch_id: int | None,
        user_id: int | None,
        event_type: str,
        created_at: int,
        metadata_json: str | None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO auth_audit_logs (company_id, branch_id, user_id, event_type, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    int(company_id),
                    int(branch_id) if branch_id is not None else None,
                    int(user_id) if user_id is not None else None,
                    str(event_type),
                    int(created_at),
                    str(metadata_json) if metadata_json is not None else None,
                ),
            )
            conn.commit()

    def mark_password_reset_token_used(self, *, company_id: int, token_id: int, used_at: int) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE password_reset_tokens
                SET used_at = ?
                WHERE company_id = ? AND id = ? AND used_at IS NULL
                """,
                (int(used_at), company_id, token_id),
            )
            if cur.rowcount != 1:
                raise sqlite3.IntegrityError("token already used or not found")
            conn.commit()

    @contextmanager
    def _connect(self):
        conn = self._persistent_conn or sqlite3.connect(self._db_path)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
        finally:
            if self._persistent_conn is None:
                conn.close()

    def _ensure_base_rbac(self, conn: sqlite3.Connection, *, company_id: int) -> None:
        conn.executemany(
            "INSERT OR IGNORE INTO roles (company_id, id, name, is_system) VALUES (?, ?, ?, 1)",
            [
                (int(company_id), 10, "Almacenista"),
                (int(company_id), 11, "Supervisor"),
                (int(company_id), 12, "Administrador"),
                (int(company_id), 13, "Superadministrador"),
            ],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO permissions (id, code, description) VALUES (?, ?, ?)",
            [
                (100, "usuarios:crear", "Crear usuarios"),
                (101, "usuarios:listar", "Listar usuarios"),
                (102, "usuarios:editar", "Editar usuarios"),
                (103, "usuarios:eliminar", "Eliminar usuarios"),
                (110, "roles:leer", "Leer roles"),
                (111, "roles:modificar", "Crear/editar roles y asignaciones"),
                (200, "inventario:leer", "Leer inventario"),
                (201, "inventario:modificar", "Modificar inventario"),
                (210, "movimientos:leer", "Leer movimientos de inventario"),
                (211, "movimientos:crear", "Crear movimientos de inventario"),
                (300, "productos:crear", "Crear productos"),
                (301, "productos:leer", "Leer productos"),
                (302, "productos:modificar", "Modificar productos"),
                (303, "productos:eliminar", "Eliminar productos"),
                (400, "proveedores:crear", "Crear proveedores"),
                (401, "proveedores:leer", "Leer proveedores"),
                (402, "proveedores:modificar", "Modificar proveedores"),
                (403, "proveedores:eliminar", "Eliminar proveedores"),
                (500, "compras:crear", "Crear órdenes de compra"),
                (501, "compras:leer", "Leer órdenes de compra"),
                (502, "compras:aprobar", "Aprobar órdenes de compra"),
                (600, "reportes:leer", "Leer reportes"),
                (700, "configuracion:modificar", "Modificar configuración"),
                (800, "empresas:crear", "Crear empresas"),
                (801, "empresas:leer", "Leer empresas"),
            ],
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
            SELECT r.company_id, r.id, p.id
            FROM roles r
            JOIN permissions p ON p.code IN ('inventario:leer', 'movimientos:leer', 'productos:leer')
            WHERE r.name = 'Almacenista' AND r.company_id = ?
            """,
            (int(company_id),),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
            SELECT r.company_id, r.id, p.id
            FROM roles r
            JOIN permissions p
              ON p.code IN ('inventario:leer', 'inventario:modificar', 'movimientos:leer', 'movimientos:crear', 'productos:leer', 'reportes:leer')
            WHERE r.name = 'Supervisor' AND r.company_id = ?
            """,
            (int(company_id),),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
            SELECT r.company_id, r.id, p.id
            FROM roles r
            JOIN permissions p ON p.code NOT IN ('empresas:crear', 'empresas:leer')
            WHERE r.name = 'Administrador' AND r.company_id = ?
            """,
            (int(company_id),),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
            SELECT r.company_id, r.id, p.id
            FROM roles r
            JOIN permissions p ON 1 = 1
            WHERE r.name = 'Superadministrador' AND r.company_id = ?
            """,
            (int(company_id),),
        )

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS companies (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  currency TEXT NOT NULL,
                  timezone TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'active',
                  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  CONSTRAINT companies_name_unique UNIQUE (name)
                );
                CREATE INDEX IF NOT EXISTS companies_created_at_idx ON companies (created_at);

                CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  email TEXT NOT NULL,
                  password_hash TEXT NOT NULL,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  verified INTEGER NOT NULL DEFAULT 0,
                  CONSTRAINT users_company_email_unique UNIQUE (company_id, email)
                );
                CREATE INDEX IF NOT EXISTS users_company_id_idx ON users (company_id);
                CREATE UNIQUE INDEX IF NOT EXISTS users_company_id_id_unique ON users (company_id, id);

                CREATE TABLE IF NOT EXISTS branches (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  address TEXT NULL,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  CONSTRAINT branches_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT branches_company_name_unique UNIQUE (company_id, name)
                );
                CREATE INDEX IF NOT EXISTS branches_company_id_idx ON branches (company_id);

                CREATE TABLE IF NOT EXISTS categories (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  CONSTRAINT categories_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT categories_company_name_unique UNIQUE (company_id, name)
                );
                CREATE INDEX IF NOT EXISTS categories_company_id_idx ON categories (company_id);

                CREATE TABLE IF NOT EXISTS products (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  category_id INTEGER NULL,
                  sku TEXT NOT NULL,
                  name TEXT NOT NULL,
                  description TEXT NULL,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  CONSTRAINT products_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT products_company_sku_unique UNIQUE (company_id, sku),
                  CONSTRAINT products_category_fk FOREIGN KEY (company_id, category_id) REFERENCES categories (company_id, id)
                );
                CREATE INDEX IF NOT EXISTS products_company_id_idx ON products (company_id);
                CREATE INDEX IF NOT EXISTS products_company_category_id_idx ON products (company_id, category_id);

                CREATE TABLE IF NOT EXISTS inventory_items (
                  company_id INTEGER NOT NULL,
                  branch_id INTEGER NOT NULL,
                  product_id INTEGER NOT NULL,
                  quantity INTEGER NOT NULL DEFAULT 0,
                  min_quantity INTEGER NOT NULL DEFAULT 0,
                  updated_at INTEGER NOT NULL,
                  CONSTRAINT inventory_items_pk PRIMARY KEY (company_id, branch_id, product_id),
                  CONSTRAINT inventory_items_branch_fk FOREIGN KEY (company_id, branch_id) REFERENCES branches (company_id, id),
                  CONSTRAINT inventory_items_product_fk FOREIGN KEY (company_id, product_id) REFERENCES products (company_id, id)
                );
                CREATE INDEX IF NOT EXISTS inventory_items_company_id_idx ON inventory_items (company_id);
                CREATE INDEX IF NOT EXISTS inventory_items_branch_id_idx ON inventory_items (company_id, branch_id);
                CREATE INDEX IF NOT EXISTS inventory_items_product_id_idx ON inventory_items (company_id, product_id);

                CREATE TABLE IF NOT EXISTS inventory_movements (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  branch_id INTEGER NOT NULL,
                  product_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  movement_type TEXT NOT NULL,
                  quantity INTEGER NOT NULL,
                  reference TEXT NULL,
                  created_at INTEGER NOT NULL,
                  CONSTRAINT inventory_movements_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT inventory_movements_branch_fk FOREIGN KEY (company_id, branch_id) REFERENCES branches (company_id, id),
                  CONSTRAINT inventory_movements_product_fk FOREIGN KEY (company_id, product_id) REFERENCES products (company_id, id),
                  CONSTRAINT inventory_movements_user_fk FOREIGN KEY (company_id, user_id) REFERENCES users (company_id, id)
                );
                CREATE INDEX IF NOT EXISTS inventory_movements_company_id_idx ON inventory_movements (company_id);
                CREATE INDEX IF NOT EXISTS inventory_movements_branch_id_idx ON inventory_movements (company_id, branch_id);
                CREATE INDEX IF NOT EXISTS inventory_movements_product_id_idx ON inventory_movements (company_id, product_id);
                CREATE INDEX IF NOT EXISTS inventory_movements_user_id_idx ON inventory_movements (company_id, user_id);
                CREATE INDEX IF NOT EXISTS inventory_movements_created_at_idx ON inventory_movements (company_id, created_at);

                CREATE TABLE IF NOT EXISTS roles (
                  company_id INTEGER NOT NULL,
                  id INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  is_system INTEGER NOT NULL DEFAULT 1,
                  CONSTRAINT roles_pk PRIMARY KEY (company_id, id),
                  CONSTRAINT roles_company_name_unique UNIQUE (company_id, name)
                );
                CREATE INDEX IF NOT EXISTS roles_company_id_idx ON roles (company_id);

                CREATE TABLE IF NOT EXISTS permissions (
                  id INTEGER PRIMARY KEY,
                  code TEXT NOT NULL,
                  description TEXT NULL,
                  CONSTRAINT permissions_code_unique UNIQUE (code)
                );

                CREATE TABLE IF NOT EXISTS role_permissions (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  role_id INTEGER NOT NULL,
                  permission_id INTEGER NOT NULL,
                  CONSTRAINT role_permissions_company_role_perm_unique UNIQUE (company_id, role_id, permission_id),
                  CONSTRAINT role_permissions_role_fk FOREIGN KEY (company_id, role_id) REFERENCES roles (company_id, id),
                  CONSTRAINT role_permissions_permission_fk FOREIGN KEY (permission_id) REFERENCES permissions (id)
                );
                CREATE INDEX IF NOT EXISTS role_permissions_company_id_idx ON role_permissions (company_id);
                CREATE INDEX IF NOT EXISTS role_permissions_role_id_idx ON role_permissions (company_id, role_id);
                CREATE INDEX IF NOT EXISTS role_permissions_permission_id_idx ON role_permissions (permission_id);

                CREATE TABLE IF NOT EXISTS user_roles (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  role_id INTEGER NOT NULL,
                  CONSTRAINT user_roles_company_user_role_unique UNIQUE (company_id, user_id, role_id),
                  CONSTRAINT user_roles_user_fk FOREIGN KEY (user_id) REFERENCES users (id),
                  CONSTRAINT user_roles_role_fk FOREIGN KEY (company_id, role_id) REFERENCES roles (company_id, id)
                );
                CREATE INDEX IF NOT EXISTS user_roles_company_id_idx ON user_roles (company_id);
                CREATE INDEX IF NOT EXISTS user_roles_user_id_idx ON user_roles (user_id);
                CREATE INDEX IF NOT EXISTS user_roles_role_id_idx ON user_roles (company_id, role_id);

                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  token_hash TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at INTEGER NOT NULL,
                  used_at INTEGER NULL,
                  CONSTRAINT prt_company_token_unique UNIQUE (company_id, token_hash),
                  CONSTRAINT prt_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
                );
                CREATE INDEX IF NOT EXISTS prt_company_id_idx ON password_reset_tokens (company_id);
                CREATE INDEX IF NOT EXISTS prt_user_id_idx ON password_reset_tokens (user_id);
                CREATE INDEX IF NOT EXISTS prt_token_hash_idx ON password_reset_tokens (token_hash);

                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  token_hash TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at INTEGER NOT NULL,
                  used_at INTEGER NULL,
                  CONSTRAINT evt_company_token_unique UNIQUE (company_id, token_hash),
                  CONSTRAINT evt_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
                );
                CREATE INDEX IF NOT EXISTS evt_company_id_idx ON email_verification_tokens (company_id);
                CREATE INDEX IF NOT EXISTS evt_user_id_idx ON email_verification_tokens (user_id);
                CREATE INDEX IF NOT EXISTS evt_token_hash_idx ON email_verification_tokens (token_hash);

                CREATE TABLE IF NOT EXISTS auth_audit_logs (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  branch_id INTEGER NULL,
                  user_id INTEGER NULL,
                  event_type TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  metadata_json TEXT NULL,
                  CONSTRAINT audit_logs_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
                );
                CREATE INDEX IF NOT EXISTS auth_audit_logs_company_id_idx ON auth_audit_logs (company_id);
                CREATE INDEX IF NOT EXISTS auth_audit_logs_company_created_at_idx ON auth_audit_logs (company_id, created_at);
                CREATE INDEX IF NOT EXISTS auth_audit_logs_user_id_idx ON auth_audit_logs (user_id);

                CREATE TABLE IF NOT EXISTS audit_logs (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  action TEXT NOT NULL,
                  resource TEXT NOT NULL,
                  details TEXT NULL,
                  timestamp INTEGER NOT NULL,
                  CONSTRAINT audit_logs_user_fk FOREIGN KEY (company_id, user_id) REFERENCES users (company_id, id)
                );
                CREATE INDEX IF NOT EXISTS audit_logs_company_id_idx ON audit_logs (company_id);
                CREATE INDEX IF NOT EXISTS audit_logs_company_user_id_idx ON audit_logs (company_id, user_id);
                CREATE INDEX IF NOT EXISTS audit_logs_company_resource_idx ON audit_logs (company_id, resource);
                CREATE INDEX IF NOT EXISTS audit_logs_company_timestamp_idx ON audit_logs (company_id, timestamp);

                INSERT OR IGNORE INTO roles (company_id, id, name, is_system) VALUES
                  (1, 10, 'Almacenista', 1),
                  (1, 11, 'Supervisor', 1),
                  (1, 12, 'Administrador', 1),
                  (1, 13, 'Superadministrador', 1),
                  (2, 10, 'Almacenista', 1),
                  (2, 11, 'Supervisor', 1),
                  (2, 12, 'Administrador', 1),
                  (2, 13, 'Superadministrador', 1);

                INSERT OR IGNORE INTO permissions (id, code, description) VALUES
                  (100, 'usuarios:crear', 'Crear usuarios'),
                  (101, 'usuarios:listar', 'Listar usuarios'),
                  (102, 'usuarios:editar', 'Editar usuarios'),
                  (103, 'usuarios:eliminar', 'Eliminar usuarios'),
                  (110, 'roles:leer', 'Leer roles'),
                  (111, 'roles:modificar', 'Crear/editar roles y asignaciones'),
                  (200, 'inventario:leer', 'Leer inventario'),
                  (201, 'inventario:modificar', 'Modificar inventario'),
                  (210, 'movimientos:leer', 'Leer movimientos de inventario'),
                  (211, 'movimientos:crear', 'Crear movimientos de inventario'),
                  (300, 'productos:crear', 'Crear productos'),
                  (301, 'productos:leer', 'Leer productos'),
                  (302, 'productos:modificar', 'Modificar productos'),
                  (303, 'productos:eliminar', 'Eliminar productos'),
                  (400, 'proveedores:crear', 'Crear proveedores'),
                  (401, 'proveedores:leer', 'Leer proveedores'),
                  (402, 'proveedores:modificar', 'Modificar proveedores'),
                  (403, 'proveedores:eliminar', 'Eliminar proveedores'),
                  (500, 'compras:crear', 'Crear órdenes de compra'),
                  (501, 'compras:leer', 'Leer órdenes de compra'),
                  (502, 'compras:aprobar', 'Aprobar órdenes de compra'),
                  (600, 'reportes:leer', 'Leer reportes'),
                  (700, 'configuracion:modificar', 'Modificar configuración'),
                  (800, 'empresas:crear', 'Crear empresas'),
                  (801, 'empresas:leer', 'Leer empresas');

                INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
                SELECT r.company_id, r.id, p.id
                FROM roles r
                JOIN permissions p ON p.code IN ('inventario:leer', 'movimientos:leer', 'productos:leer')
                WHERE r.name = 'Almacenista' AND r.company_id IN (1, 2);

                INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
                SELECT r.company_id, r.id, p.id
                FROM roles r
                JOIN permissions p
                  ON p.code IN ('inventario:leer', 'inventario:modificar', 'movimientos:leer', 'movimientos:crear', 'productos:leer', 'reportes:leer')
                WHERE r.name = 'Supervisor' AND r.company_id IN (1, 2);

                INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
                SELECT r.company_id, r.id, p.id
                FROM roles r
                JOIN permissions p ON p.code NOT IN ('empresas:crear', 'empresas:leer')
                WHERE r.name = 'Administrador' AND r.company_id IN (1, 2);

                INSERT OR IGNORE INTO role_permissions (company_id, role_id, permission_id)
                SELECT r.company_id, r.id, p.id
                FROM roles r
                JOIN permissions p ON 1 = 1
                WHERE r.name = 'Superadministrador' AND r.company_id IN (1, 2);
                """
            )
            cols = [row[1] for row in conn.execute("PRAGMA table_info(companies)").fetchall()]
            if "status" not in cols:
                conn.execute("ALTER TABLE companies ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            conn.commit()
