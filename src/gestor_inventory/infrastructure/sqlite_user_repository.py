import sqlite3
from contextlib import contextmanager
import time
import unicodedata

from gestor_inventory.application.list_users import UserListItem
from gestor_inventory.domain.errors import EmailAlreadyExistsError, ValidationError
from gestor_inventory.domain.company import Company
from gestor_inventory.domain.company_setting import CompanySetting
from gestor_inventory.domain.operational import Branch, InventoryItem, InventoryMovement, Product, Supplier
from gestor_inventory.domain.operational import Category
from gestor_inventory.domain.purchases import PurchaseOrder
from gestor_inventory.domain.rbac import Permission, Role
from gestor_inventory.domain.user import User


class SqliteUserRepository:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._persistent_conn = (
            sqlite3.connect(":memory:", check_same_thread=False) if db_path == ":memory:" else None
        )
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

    def get_user_for_refresh(self, *, company_id: int, user_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, company_id, email, is_active, verified
                FROM users
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(user_id)),
            ).fetchone()
            if row is None:
                return None
            user_id_v, company_id_v, email_v, is_active, verified = row
            return {
                "id": int(user_id_v),
                "company_id": int(company_id_v),
                "email": str(email_v),
                "is_active": bool(is_active),
                "verified": bool(verified),
            }

    def get_user_for_verification(self, *, company_id: int, email: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, company_id, email, is_active, verified
                FROM users
                WHERE company_id = ? AND email = ?
                LIMIT 1
                """,
                (int(company_id), str(email)),
            ).fetchone()
            if row is None:
                return None
            user_id_v, company_id_v, email_v, is_active, verified = row
            return {
                "id": int(user_id_v),
                "company_id": int(company_id_v),
                "email": str(email_v),
                "is_active": bool(is_active),
                "verified": bool(verified),
            }

    def get_user_by_id(self, *, company_id: int, user_id: int) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, company_id, email, password_hash, is_active, verified
                FROM users
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(user_id)),
            ).fetchone()
            if row is None:
                return None
            user_id_v, company_id_v, email_v, password_hash, is_active, verified = row
            return User(
                id=int(user_id_v),
                company_id=int(company_id_v),
                email=str(email_v),
                password_hash=str(password_hash),
                is_active=bool(is_active),
                verified=bool(verified),
            )

    def count_users_by_company(self, *, company_id: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*)
                FROM users
                WHERE company_id = ?
                """,
                (int(company_id),),
            ).fetchone()
            return 0 if row is None else int(row[0])

    def list_users_by_company(self, *, company_id: int, limit: int, offset: int) -> list[UserListItem]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    u.id,
                    u.company_id,
                    u.email,
                    u.is_active,
                    u.verified,
                    COALESCE(
                        (
                            SELECT GROUP_CONCAT(role_name, '|')
                            FROM (
                                SELECT r.name AS role_name
                                FROM user_roles ur
                                JOIN roles r ON r.company_id = ur.company_id AND r.id = ur.role_id
                                WHERE ur.company_id = u.company_id AND ur.user_id = u.id
                                ORDER BY r.id
                            )
                        ),
                        ''
                    ) AS role_names
                FROM users u
                WHERE u.company_id = ?
                ORDER BY u.id
                LIMIT ? OFFSET ?
                """,
                (int(company_id), int(limit), int(offset)),
            ).fetchall()
            items: list[UserListItem] = []
            for user_id, company_id_v, email, is_active, verified, role_names in rows:
                roles = [str(name) for name in str(role_names or "").split("|") if str(name).strip()]
                items.append(
                    UserListItem(
                        id=int(user_id),
                        company_id=int(company_id_v),
                        email=str(email),
                        is_active=bool(is_active),
                        verified=bool(verified),
                        roles=roles,
                    )
                )
            return items

    def update_user(
        self,
        *,
        company_id: int,
        user_id: int,
        email: str | None,
        password_hash: str | None,
        is_active: bool | None,
        verified: bool | None,
    ) -> User:
        fields: list[str] = []
        params: list[object] = []
        if email is not None:
            fields.append("email = ?")
            params.append(str(email))
        if password_hash is not None:
            fields.append("password_hash = ?")
            params.append(str(password_hash))
        if is_active is not None:
            fields.append("is_active = ?")
            params.append(1 if bool(is_active) else 0)
        if verified is not None:
            fields.append("verified = ?")
            params.append(1 if bool(verified) else 0)
        if not fields:
            raise sqlite3.IntegrityError("no fields to update")

        params.append(int(company_id))
        params.append(int(user_id))

        with self._connect() as conn:
            try:
                sql = f"UPDATE users SET {', '.join(fields)} WHERE company_id = ? AND id = ?"
                cur = conn.execute(sql, params)
                if int(cur.rowcount) != 1:
                    raise sqlite3.IntegrityError("user not found")
                conn.commit()
            except sqlite3.IntegrityError as e:
                conn.rollback()
                if "users.company_id" in str(e) or "users_company_email_unique" in str(e) or "users(company_id,email)" in str(e):
                    raise EmailAlreadyExistsError() from None
                raise

        user = self.get_user_by_id(company_id=int(company_id), user_id=int(user_id))
        if user is None:
            raise sqlite3.IntegrityError("user not found")
        return user

    def deactivate_user(self, *, company_id: int, user_id: int) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT is_active FROM users WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(user_id)),
            ).fetchone()
            if row is None:
                return "not_found"
            is_active = bool(row[0])
            if not is_active:
                return "already_inactive"
            cur = conn.execute(
                "UPDATE users SET is_active = 0 WHERE company_id = ? AND id = ?",
                (int(company_id), int(user_id)),
            )
            if int(cur.rowcount) != 1:
                return "not_found"
            conn.commit()
            return "changed"

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

    def create_refresh_token(
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
                INSERT INTO refresh_tokens (company_id, user_id, token_hash, expires_at, created_at, used_at)
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

    def consume_refresh_token(self, *, company_id: int, token_hash: str, now: int) -> tuple[str, int | None]:
        with self._connect() as conn:
            conn.execute("BEGIN")
            row = conn.execute(
                """
                SELECT id, user_id, expires_at, used_at
                FROM refresh_tokens
                WHERE company_id = ? AND token_hash = ?
                LIMIT 1
                """,
                (int(company_id), str(token_hash)),
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

            cur = conn.execute(
                """
                UPDATE refresh_tokens
                SET used_at = ?
                WHERE company_id = ? AND id = ? AND used_at IS NULL
                """,
                (int(now), int(company_id), int(token_id)),
            )
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                return "already_used", int(user_id)

            conn.execute("COMMIT")
            return "ok", int(user_id)

    def invalidate_refresh_token(self, *, company_id: int, token_hash: str, now: int) -> tuple[str, int | None]:
        with self._connect() as conn:
            conn.execute("BEGIN")
            row = conn.execute(
                """
                SELECT id, user_id, expires_at, used_at
                FROM refresh_tokens
                WHERE company_id = ? AND token_hash = ?
                LIMIT 1
                """,
                (int(company_id), str(token_hash)),
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

            cur = conn.execute(
                """
                UPDATE refresh_tokens
                SET used_at = ?
                WHERE company_id = ? AND id = ? AND used_at IS NULL
                """,
                (int(now), int(company_id), int(token_id)),
            )
            if cur.rowcount != 1:
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

    def create_category(
        self,
        *,
        company_id: int,
        name: str,
        description: str | None = None,
        status: str = "active",
        is_active: bool | None = None,
    ) -> Category:
        status_v = str(status)
        if is_active is not None:
            status_v = "active" if bool(is_active) else "inactive"
        is_active_v = status_v == "active"
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO categories (company_id, name, description, status, is_active)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(company_id), str(name), (str(description) if description is not None else None), str(status_v), 1 if is_active_v else 0),
            )
            category_id = int(cur.lastrowid)
            conn.commit()
            return Category(
                company_id=int(company_id),
                id=category_id,
                name=str(name),
                description=(str(description) if description is not None else None),
                status=str(status_v),
                is_active=bool(is_active_v),
            )

    def get_category_by_id(self, *, company_id: int, category_id: int) -> Category | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, name, description, status, is_active
                FROM categories
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(category_id)),
            ).fetchone()
            if row is None:
                return None
            company_id_v, category_id_v, name, description, status, is_active = row
            status_v = str(status) if status is not None else ("active" if bool(is_active) else "inactive")
            description_v = str(description) if description is not None else None
            return Category(
                company_id=int(company_id_v),
                id=int(category_id_v),
                name=str(name),
                description=description_v,
                status=status_v,
                is_active=bool(is_active),
            )

    def list_categories(self, *, company_id: int, status: str | None) -> list[Category]:
        with self._connect() as conn:
            sql = """
            SELECT company_id, id, name, description, status, is_active
            FROM categories
            WHERE company_id = ?
            """
            params: list[object] = [int(company_id)]
            if status is not None:
                sql += " AND status = ?"
                params.append(str(status))
            sql += " ORDER BY id"
            rows = conn.execute(sql, params).fetchall()
            return [
                Category(
                    company_id=int(company_id_v),
                    id=int(category_id_v),
                    name=str(name_v),
                    description=str(description_v) if description_v is not None else None,
                    status=str(status_v) if status_v is not None else ("active" if bool(is_active_v) else "inactive"),
                    is_active=bool(is_active_v),
                )
                for (company_id_v, category_id_v, name_v, description_v, status_v, is_active_v) in rows
            ]

    def create_branch(
        self,
        *,
        company_id: int,
        name: str,
        address: str | None,
        city: str | None = None,
        country: str | None = None,
        status: str = "active",
        is_active: bool,
    ) -> Branch:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO branches (company_id, name, address, city, country, status, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(company_id),
                    str(name),
                    str(address) if address is not None else None,
                    str(city) if city is not None else None,
                    str(country) if country is not None else None,
                    str(status),
                    1 if is_active else 0,
                ),
            )
            branch_id = int(cur.lastrowid)
            conn.commit()
            return Branch(
                company_id=int(company_id),
                id=branch_id,
                name=str(name),
                address=address,
                city=city,
                country=country,
                status=str(status),
                is_active=bool(is_active),
            )

    def list_branches(self, *, company_id: int, city: str | None, status: str | None) -> list[Branch]:
        with self._connect() as conn:
            sql = """
            SELECT company_id, id, name, address, city, country, status, is_active
            FROM branches
            WHERE company_id = ?
            """
            params: list[object] = [int(company_id)]
            if city is not None:
                sql += " AND city = ?"
                params.append(str(city))
            if status is not None:
                sql += " AND status = ?"
                params.append(str(status))
            sql += " ORDER BY id"
            rows = conn.execute(sql, params).fetchall()
            return [
                Branch(
                    company_id=int(company_id_v),
                    id=int(branch_id),
                    name=str(name),
                    address=str(address) if address is not None else None,
                    city=str(city_v) if city_v is not None else None,
                    country=str(country_v) if country_v is not None else None,
                    status=str(status_v),
                    is_active=bool(is_active),
                )
                for (company_id_v, branch_id, name, address, city_v, country_v, status_v, is_active) in rows
            ]

    def get_branch_by_id(self, *, company_id: int, branch_id: int) -> Branch | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, name, address, city, country, status, is_active
                FROM branches
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(branch_id)),
            ).fetchone()
            if row is None:
                return None
            company_id_v, branch_id_v, name, address, city_v, country_v, status_v, is_active = row
            return Branch(
                company_id=int(company_id_v),
                id=int(branch_id_v),
                name=str(name),
                address=str(address) if address is not None else None,
                city=str(city_v) if city_v is not None else None,
                country=str(country_v) if country_v is not None else None,
                status=str(status_v),
                is_active=bool(is_active),
            )

    def update_branch(
        self,
        *,
        company_id: int,
        branch_id: int,
        name: str | None,
        address: str | None,
        city: str | None,
        country: str | None,
    ) -> Branch:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE branches
                SET
                  name = COALESCE(?, name),
                  address = COALESCE(?, address),
                  city = COALESCE(?, city),
                  country = COALESCE(?, country)
                WHERE company_id = ? AND id = ?
                """,
                (
                    str(name) if name is not None else None,
                    str(address) if address is not None else None,
                    str(city) if city is not None else None,
                    str(country) if country is not None else None,
                    int(company_id),
                    int(branch_id),
                ),
            )
            if int(cur.rowcount) != 1:
                raise sqlite3.IntegrityError("branch not found")
            conn.commit()
        branch = self.get_branch_by_id(company_id=int(company_id), branch_id=int(branch_id))
        if branch is None:
            raise sqlite3.IntegrityError("branch not found")
        return branch

    def branch_has_inventory(self, *, company_id: int, branch_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM inventory_items
                WHERE company_id = ? AND branch_id = ?
                LIMIT 1
                """,
                (int(company_id), int(branch_id)),
            ).fetchone()
            return row is not None

    def deactivate_branch(self, *, company_id: int, branch_id: int) -> str:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE branches
                SET status = 'inactive', is_active = 0
                WHERE company_id = ? AND id = ? AND status <> 'inactive'
                """,
                (int(company_id), int(branch_id)),
            )
            conn.commit()
            if int(cur.rowcount) == 1:
                return "changed"
            row = conn.execute(
                "SELECT status FROM branches WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(branch_id)),
            ).fetchone()
            if row is None:
                return "not_found"
            (status,) = row
            return "already_inactive" if str(status) == "inactive" else "not_found"

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
        category_id: int,
        sku: str,
        barcode: str | None = None,
        name: str,
        description: str | None,
        stock_minimum: int = 0,
        status: str = "active",
        is_active: bool | None = None,
        created_at: int | None = None,
        updated_at: int | None = None,
    ) -> Product:
        status_v = str(status)
        if is_active is not None:
            status_v = "active" if bool(is_active) else "inactive"
        is_active_v = status_v == "active"
        now = int(time.time())
        created_at_v = int(now if created_at is None else created_at)
        updated_at_v = int(now if updated_at is None else updated_at)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO products (
                  company_id, category_id, sku, barcode, name, description, stock_minimum, status, is_active, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(company_id),
                    int(category_id),
                    str(sku),
                    str(barcode) if barcode is not None else None,
                    str(name),
                    str(description) if description is not None else None,
                    int(stock_minimum),
                    str(status_v),
                    1 if is_active_v else 0,
                    int(created_at_v),
                    int(updated_at_v),
                ),
            )
            product_id = int(cur.lastrowid)
            conn.commit()
            return Product(
                company_id=int(company_id),
                id=product_id,
                category_id=int(category_id),
                sku=str(sku),
                barcode=str(barcode) if barcode is not None else None,
                name=str(name),
                description=description,
                stock_minimum=int(stock_minimum),
                status=str(status_v),
                is_active=bool(is_active_v),
                created_at=int(created_at_v),
                updated_at=int(updated_at_v),
            )

    def get_product_by_sku(self, *, company_id: int, sku: str) -> Product | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, category_id, sku, barcode, name, description, stock_minimum, status, is_active, created_at, updated_at
                FROM products
                WHERE company_id = ? AND sku = ?
                LIMIT 1
                """,
                (int(company_id), str(sku)),
            ).fetchone()
            if row is None:
                return None
            (
                company_id_v,
                product_id,
                category_id,
                sku_v,
                barcode,
                name,
                description,
                stock_minimum,
                status,
                is_active,
                created_at,
                updated_at,
            ) = row
            status_v = str(status) if status is not None else ("active" if bool(is_active) else "inactive")
            return Product(
                company_id=int(company_id_v),
                id=int(product_id),
                category_id=int(category_id),
                sku=str(sku_v),
                barcode=str(barcode) if barcode is not None else None,
                name=str(name),
                description=str(description) if description is not None else None,
                stock_minimum=int(stock_minimum) if stock_minimum is not None else 0,
                status=status_v,
                is_active=bool(is_active),
                created_at=int(created_at) if created_at is not None else 1,
                updated_at=int(updated_at) if updated_at is not None else 1,
            )

    def get_product_by_id(self, *, company_id: int, product_id: int) -> Product | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, category_id, sku, barcode, name, description, stock_minimum, status, is_active, created_at, updated_at
                FROM products
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(product_id)),
            ).fetchone()
            if row is None:
                return None
            (
                company_id_v,
                product_id_v,
                category_id,
                sku_v,
                barcode,
                name,
                description,
                stock_minimum,
                status,
                is_active,
                created_at,
                updated_at,
            ) = row
            status_v = str(status) if status is not None else ("active" if bool(is_active) else "inactive")
            return Product(
                company_id=int(company_id_v),
                id=int(product_id_v),
                category_id=int(category_id),
                sku=str(sku_v),
                barcode=str(barcode) if barcode is not None else None,
                name=str(name),
                description=str(description) if description is not None else None,
                stock_minimum=int(stock_minimum) if stock_minimum is not None else 0,
                status=status_v,
                is_active=bool(is_active),
                created_at=int(created_at) if created_at is not None else 1,
                updated_at=int(updated_at) if updated_at is not None else 1,
            )

    def get_product_by_barcode(self, *, company_id: int, barcode: str) -> Product | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, category_id, sku, barcode, name, description, stock_minimum, status, is_active, created_at, updated_at
                FROM products
                WHERE company_id = ? AND barcode = ?
                LIMIT 1
                """,
                (int(company_id), str(barcode)),
            ).fetchone()
            if row is None:
                return None
            (
                company_id_v,
                product_id,
                category_id,
                sku_v,
                barcode_v,
                name,
                description,
                stock_minimum,
                status,
                is_active,
                created_at,
                updated_at,
            ) = row
            status_v = str(status) if status is not None else ("active" if bool(is_active) else "inactive")
            return Product(
                company_id=int(company_id_v),
                id=int(product_id),
                category_id=int(category_id),
                sku=str(sku_v),
                barcode=str(barcode_v) if barcode_v is not None else None,
                name=str(name),
                description=str(description) if description is not None else None,
                stock_minimum=int(stock_minimum) if stock_minimum is not None else 0,
                status=status_v,
                is_active=bool(is_active),
                created_at=int(created_at) if created_at is not None else 1,
                updated_at=int(updated_at) if updated_at is not None else 1,
            )

    def update_product(
        self,
        *,
        company_id: int,
        product_id: int,
        name: str | None,
        sku: str | None,
        barcode: str | None,
        category_id: int | None,
        description: str | None,
        stock_minimum: int | None,
        status: str | None,
    ) -> Product:
        fields: list[str] = []
        params: list[object] = []
        if name is not None:
            fields.append("name = ?")
            params.append(str(name))
        if sku is not None:
            fields.append("sku = ?")
            params.append(str(sku))
        if barcode is not None:
            fields.append("barcode = ?")
            params.append(str(barcode))
        if category_id is not None:
            fields.append("category_id = ?")
            params.append(int(category_id))
        if description is not None:
            fields.append("description = ?")
            params.append(str(description))
        if stock_minimum is not None:
            fields.append("stock_minimum = ?")
            params.append(int(stock_minimum))
        if status is not None:
            fields.append("status = ?")
            params.append(str(status))
            fields.append("is_active = ?")
            params.append(1 if str(status) == "active" else 0)

        now = int(time.time())
        fields.append("updated_at = ?")
        params.append(int(now))
        params.append(int(product_id))
        params.append(int(company_id))

        with self._connect() as conn:
            sql = f"UPDATE products SET {', '.join(fields)} WHERE id = ? AND company_id = ?"
            cur = conn.execute(sql, params)
            if int(cur.rowcount) != 1:
                raise sqlite3.IntegrityError("product not found")
            conn.commit()
            product = self.get_product_by_id(company_id=int(company_id), product_id=int(product_id))
            if product is None:
                raise sqlite3.IntegrityError("product not found")
            return product

    def count_products(self, *, company_id: int, category_id: int | None, status: str | None, search: str | None) -> int:
        with self._connect() as conn:
            sql = "SELECT COUNT(1) FROM products WHERE company_id = ?"
            params: list[object] = [int(company_id)]
            if category_id is not None:
                sql += " AND category_id = ?"
                params.append(int(category_id))
            if status is not None:
                sql += " AND status = ?"
                params.append(str(status))
            if search is not None:
                search_v = self._normalize_search(str(search))
                like = f"%{search_v}%"
                name_norm = (
                    "lower(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(name,"
                    "'Á','A'),'á','a'),'À','A'),'à','a'),'É','E'),'é','e'),'Í','I'),'í','i'),'Ó','O'),'ó','o'),'Ú','U'),'ú','u'),"
                    "'Ñ','N'),'ñ','n'))"
                )
                sql += f" AND ({name_norm} LIKE ? OR lower(sku) LIKE ? OR lower(barcode) LIKE ?)"
                params.extend([like, like, like])
            row = conn.execute(sql, params).fetchone()
            return 0 if row is None else int(row[0])

    def list_products(
        self,
        *,
        company_id: int,
        category_id: int | None,
        status: str | None,
        search: str | None,
        limit: int,
        offset: int,
    ) -> list[Product]:
        with self._connect() as conn:
            sql = """
            SELECT company_id, id, category_id, sku, barcode, name, description, stock_minimum, status, is_active, created_at, updated_at
            FROM products
            WHERE company_id = ?
            """
            params: list[object] = [int(company_id)]
            if category_id is not None:
                sql += " AND category_id = ?"
                params.append(int(category_id))
            if status is not None:
                sql += " AND status = ?"
                params.append(str(status))
            if search is not None:
                search_v = self._normalize_search(str(search))
                like = f"%{search_v}%"
                name_norm = (
                    "lower(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(name,"
                    "'Á','A'),'á','a'),'À','A'),'à','a'),'É','E'),'é','e'),'Í','I'),'í','i'),'Ó','O'),'ó','o'),'Ú','U'),'ú','u'),"
                    "'Ñ','N'),'ñ','n'))"
                )
                sql += f" AND ({name_norm} LIKE ? OR lower(sku) LIKE ? OR lower(barcode) LIKE ?)"
                params.extend([like, like, like])
            sql += " ORDER BY id LIMIT ? OFFSET ?"
            params.append(int(limit))
            params.append(int(offset))
            rows = conn.execute(sql, params).fetchall()
            products: list[Product] = []
            for (
                company_id_v,
                product_id_v,
                category_id_v,
                sku_v,
                barcode_v,
                name_v,
                description,
                stock_minimum,
                status_v,
                is_active,
                created_at,
                updated_at,
            ) in rows:
                status_out = str(status_v) if status_v is not None else ("active" if bool(is_active) else "inactive")
                products.append(
                    Product(
                        company_id=int(company_id_v),
                        id=int(product_id_v),
                        category_id=int(category_id_v),
                        sku=str(sku_v),
                        barcode=str(barcode_v) if barcode_v is not None else None,
                        name=str(name_v),
                        description=str(description) if description is not None else None,
                        stock_minimum=int(stock_minimum) if stock_minimum is not None else 0,
                        status=status_out,
                        is_active=bool(is_active),
                        created_at=int(created_at) if created_at is not None else 1,
                        updated_at=int(updated_at) if updated_at is not None else 1,
                    )
                )
            return products

    def _normalize_search(self, value: str) -> str:
        v = unicodedata.normalize("NFKD", str(value))
        v = "".join(ch for ch in v if not unicodedata.combining(ch))
        return v.lower().strip()

    def company_is_active(self, *, company_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM companies WHERE id = ? AND status = 'active' LIMIT 1",
                (int(company_id),),
            ).fetchone()
            return row is not None

    def product_belongs_to_company(self, *, company_id: int, product_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM products WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(product_id)),
            ).fetchone()
            return row is not None

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
                default_branch_id=None,
                created_at=int(created_at),
            )

    def create_supplier(
        self,
        *,
        company_id: int,
        name: str,
        document_id: str | None,
        contact_email: str | None,
        phone: str | None,
        status: str,
        created_at: int,
        updated_at: int,
    ) -> Supplier:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO suppliers (company_id, name, document_id, contact_email, phone, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(company_id),
                    str(name),
                    (str(document_id) if document_id is not None else None),
                    (str(contact_email) if contact_email is not None else None),
                    (str(phone) if phone is not None else None),
                    str(status),
                    int(created_at),
                    int(updated_at),
                ),
            )
            supplier_id = int(cur.lastrowid)
            conn.commit()
            return Supplier(
                company_id=int(company_id),
                id=supplier_id,
                name=str(name),
                document_id=(str(document_id) if document_id is not None else None),
                contact_email=(str(contact_email) if contact_email is not None else None),
                phone=(str(phone) if phone is not None else None),
                status=str(status),
                created_at=int(created_at),
                updated_at=int(updated_at),
            )

    def get_supplier_by_id(self, *, company_id: int, supplier_id: int) -> Supplier | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT company_id, id, name, document_id, contact_email, phone, status, created_at, updated_at
                FROM suppliers
                WHERE company_id = ? AND id = ?
                LIMIT 1
                """,
                (int(company_id), int(supplier_id)),
            ).fetchone()
            if row is None:
                return None
            (
                company_id_v,
                supplier_id_v,
                name_v,
                document_id_v,
                contact_email,
                phone,
                status_v,
                created_at,
                updated_at,
            ) = row
            return Supplier(
                company_id=int(company_id_v),
                id=int(supplier_id_v),
                name=str(name_v),
                document_id=str(document_id_v) if document_id_v is not None else None,
                contact_email=str(contact_email) if contact_email is not None else None,
                phone=str(phone) if phone is not None else None,
                status=str(status_v),
                created_at=int(created_at),
                updated_at=int(updated_at),
            )

    def update_supplier(
        self,
        *,
        company_id: int,
        supplier_id: int,
        name: str | None,
        contact_email: str | None,
        phone: str | None,
        status: str | None,
    ) -> Supplier:
        fields: list[str] = []
        params: list[object] = []
        if name is not None:
            fields.append("name = ?")
            params.append(str(name))
        if contact_email is not None:
            fields.append("contact_email = ?")
            params.append(str(contact_email))
        if phone is not None:
            fields.append("phone = ?")
            params.append(str(phone))
        if status is not None:
            fields.append("status = ?")
            params.append(str(status))
        now = int(time.time())
        fields.append("updated_at = ?")
        params.append(int(now))
        params.append(int(supplier_id))
        params.append(int(company_id))

        with self._connect() as conn:
            sql = f"UPDATE suppliers SET {', '.join(fields)} WHERE id = ? AND company_id = ?"
            cur = conn.execute(sql, params)
            if int(cur.rowcount) != 1:
                raise sqlite3.IntegrityError("supplier not found")
            conn.commit()
            supplier = self.get_supplier_by_id(company_id=int(company_id), supplier_id=int(supplier_id))
            if supplier is None:
                raise sqlite3.IntegrityError("supplier not found")
            return supplier

    def deactivate_supplier(self, *, company_id: int, supplier_id: int) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM suppliers WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(supplier_id)),
            ).fetchone()
            if row is None:
                return "not_found"
            status = str(row[0])
            if status == "inactive":
                return "already_inactive"
            now = int(time.time())
            cur = conn.execute(
                "UPDATE suppliers SET status = 'inactive', updated_at = ? WHERE id = ? AND company_id = ?",
                (int(now), int(supplier_id), int(company_id)),
            )
            if int(cur.rowcount) != 1:
                return "not_found"
            conn.commit()
            return "changed"

    def count_suppliers(
        self,
        *,
        company_id: int,
        name: str | None,
        document_id: str | None,
        status: str | None,
    ) -> int:
        with self._connect() as conn:
            sql = "SELECT COUNT(1) FROM suppliers WHERE company_id = ?"
            params: list[object] = [int(company_id)]
            if name is not None:
                sql += " AND name LIKE ?"
                params.append(f"%{str(name)}%")
            if document_id is not None:
                sql += " AND document_id = ?"
                params.append(str(document_id))
            if status is not None:
                sql += " AND status = ?"
                params.append(str(status))
            row = conn.execute(sql, params).fetchone()
            return 0 if row is None else int(row[0])

    def list_suppliers(
        self,
        *,
        company_id: int,
        name: str | None,
        document_id: str | None,
        status: str | None,
        limit: int,
        offset: int,
    ) -> list[Supplier]:
        with self._connect() as conn:
            sql = """
            SELECT company_id, id, name, document_id, contact_email, phone, status, created_at, updated_at
            FROM suppliers
            WHERE company_id = ?
            """
            params: list[object] = [int(company_id)]
            if name is not None:
                sql += " AND name LIKE ?"
                params.append(f"%{str(name)}%")
            if document_id is not None:
                sql += " AND document_id = ?"
                params.append(str(document_id))
            if status is not None:
                sql += " AND status = ?"
                params.append(str(status))
            sql += " ORDER BY id LIMIT ? OFFSET ?"
            params.append(int(limit))
            params.append(int(offset))
            rows = conn.execute(sql, params).fetchall()
            return [
                Supplier(
                    company_id=int(company_id_v),
                    id=int(supplier_id),
                    name=str(name_v),
                    document_id=str(document_id_v) if document_id_v is not None else None,
                    contact_email=str(contact_email) if contact_email is not None else None,
                    phone=str(phone) if phone is not None else None,
                    status=str(status_v),
                    created_at=int(created_at),
                    updated_at=int(updated_at),
                )
                for (
                    company_id_v,
                    supplier_id,
                    name_v,
                    document_id_v,
                    contact_email,
                    phone,
                    status_v,
                    created_at,
                    updated_at,
                ) in rows
            ]

    def supplier_exists(self, *, supplier_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM suppliers WHERE id = ? LIMIT 1", (int(supplier_id),)).fetchone()
            return row is not None

    def supplier_belongs_to_company(self, *, company_id: int, supplier_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM suppliers WHERE company_id = ? AND id = ? LIMIT 1",
                (int(company_id), int(supplier_id)),
            ).fetchone()
            return row is not None

    def supplier_is_active(self, *, company_id: int, supplier_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM suppliers WHERE company_id = ? AND id = ? AND status = 'active' LIMIT 1",
                (int(company_id), int(supplier_id)),
            ).fetchone()
            return row is not None

    def create_purchase_order(
        self,
        *,
        company_id: int,
        supplier_id: int,
        status: str,
        created_at: int,
        updated_at: int,
    ) -> PurchaseOrder:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO purchase_orders (company_id, supplier_id, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(company_id), int(supplier_id), str(status), int(created_at), int(updated_at)),
            )
            po_id = int(cur.lastrowid)
            conn.commit()
            return PurchaseOrder(
                company_id=int(company_id),
                id=po_id,
                supplier_id=int(supplier_id),
                status=str(status),
                created_at=int(created_at),
                updated_at=int(updated_at),
            )

    def count_active_companies(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(1) FROM companies WHERE status = 'active'").fetchone()
            return 0 if row is None else int(row[0])

    def list_active_companies(self, *, limit: int, offset: int) -> list[Company]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, currency, timezone, status, default_branch_id, created_at
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
                    default_branch_id=int(default_branch_id) if default_branch_id is not None else None,
                    created_at=int(created_at),
                )
                for (company_id, name, currency, timezone, status, default_branch_id, created_at) in rows
            ]

    def update_company_default_branch(self, *, company_id: int, default_branch_id: int | None) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE companies SET default_branch_id = ? WHERE id = ?",
                (int(default_branch_id) if default_branch_id is not None else None, int(company_id)),
            )
            if int(cur.rowcount) != 1:
                raise sqlite3.IntegrityError("company not found")
            conn.commit()

    def get_company_settings(self, *, company_id: int) -> list[CompanySetting]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, company_id, setting_key, setting_value, created_at, updated_at
                FROM company_settings
                WHERE company_id = ?
                ORDER BY setting_key
                """,
                (int(company_id),),
            ).fetchall()
            return [
                CompanySetting(
                    id=int(setting_id),
                    company_id=int(company_id_v),
                    setting_key=str(setting_key),
                    setting_value=str(setting_value),
                    created_at=int(created_at),
                    updated_at=int(updated_at),
                )
                for (setting_id, company_id_v, setting_key, setting_value, created_at, updated_at) in rows
            ]

    def upsert_company_setting(self, *, company_id: int, setting_key: str, setting_value: str, now: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO company_settings (company_id, setting_key, setting_value, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(company_id, setting_key)
                DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at
                """,
                (int(company_id), str(setting_key), str(setting_value), int(now), int(now)),
            )
            conn.commit()

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

    def register_inventory_movement(
        self,
        *,
        company_id: int,
        branch_id: int,
        product_id: int,
        user_id: int,
        movement_type: str,
        quantity: int,
        reference: str | None,
    ) -> tuple[InventoryItem, InventoryMovement]:
        with self._connect() as conn:
            now = int(time.time())
            conn.execute("BEGIN")
            try:
                row = conn.execute(
                    """
                    SELECT quantity, min_quantity, updated_at
                    FROM inventory_items
                    WHERE company_id = ? AND branch_id = ? AND product_id = ?
                    LIMIT 1
                    """,
                    (int(company_id), int(branch_id), int(product_id)),
                ).fetchone()

                current_quantity = int(row[0]) if row is not None else 0
                min_quantity = int(row[1]) if row is not None else 0
                delta = int(quantity) if str(movement_type) == "entrada" else -int(quantity)
                new_quantity = current_quantity + delta

                if new_quantity < 0:
                    raise ValidationError("stock insuficiente")

                conn.execute(
                    """
                    INSERT INTO inventory_items (company_id, branch_id, product_id, quantity, min_quantity, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(company_id, branch_id, product_id)
                    DO UPDATE SET quantity = excluded.quantity, min_quantity = excluded.min_quantity, updated_at = excluded.updated_at
                    """,
                    (int(company_id), int(branch_id), int(product_id), int(new_quantity), int(min_quantity), int(now)),
                )

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
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

            return (
                InventoryItem(
                    company_id=int(company_id),
                    branch_id=int(branch_id),
                    product_id=int(product_id),
                    quantity=int(new_quantity),
                    min_quantity=int(min_quantity),
                    updated_at=int(now),
                ),
                InventoryMovement(
                    company_id=int(company_id),
                    id=movement_id,
                    branch_id=int(branch_id),
                    product_id=int(product_id),
                    user_id=int(user_id),
                    movement_type=str(movement_type),
                    quantity=int(quantity),
                    reference=reference,
                    created_at=int(now),
                ),
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
                (304, "productos:editar", "Editar productos"),
                (320, "categorias:leer", "Leer categorías"),
                (400, "proveedores:crear", "Crear proveedores"),
                (401, "proveedores:leer", "Leer proveedores"),
                (402, "proveedores:modificar", "Modificar proveedores"),
                (403, "proveedores:eliminar", "Eliminar proveedores"),
                (404, "proveedores:editar", "Editar proveedores"),
                (500, "compras:crear", "Crear órdenes de compra"),
                (501, "compras:leer", "Leer órdenes de compra"),
                (502, "compras:aprobar", "Aprobar órdenes de compra"),
                (600, "reportes:leer", "Leer reportes"),
                (700, "configuracion:modificar", "Modificar configuración"),
                (701, "configuracion:leer", "Leer configuración"),
                (702, "configuracion:editar", "Editar configuración"),
                (800, "empresas:crear", "Crear empresas"),
                (801, "empresas:leer", "Leer empresas"),
                (802, "empresas:editar", "Editar empresas"),
                (810, "sucursal:crear", "Crear sucursales"),
                (811, "sucursales:leer", "Leer sucursales"),
                (812, "sucursales:editar", "Editar sucursales"),
                (813, "sucursales:eliminar", "Eliminar (desactivar) sucursales"),
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
            JOIN permissions p ON p.code NOT IN ('empresas:crear', 'empresas:leer', 'empresas:editar')
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
                  default_branch_id INTEGER NULL,
                  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  CONSTRAINT companies_name_unique UNIQUE (name),
                  CONSTRAINT companies_default_branch_fk FOREIGN KEY (default_branch_id) REFERENCES branches (id)
                );
                CREATE INDEX IF NOT EXISTS companies_created_at_idx ON companies (created_at);

                CREATE TABLE IF NOT EXISTS company_settings (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  setting_key TEXT NOT NULL,
                  setting_value TEXT NOT NULL,
                  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  CONSTRAINT company_settings_company_fk FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
                  CONSTRAINT company_settings_company_key_unique UNIQUE (company_id, setting_key)
                );
                CREATE INDEX IF NOT EXISTS company_settings_company_id_idx ON company_settings (company_id);

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
                  city TEXT NULL,
                  country TEXT NULL,
                  status TEXT NOT NULL DEFAULT 'active',
                  is_active INTEGER NOT NULL DEFAULT 1,
                  CONSTRAINT branches_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT branches_company_name_unique UNIQUE (company_id, name)
                );
                CREATE INDEX IF NOT EXISTS branches_company_id_idx ON branches (company_id);
                CREATE INDEX IF NOT EXISTS idx_branches_company_id ON branches (company_id);
                CREATE INDEX IF NOT EXISTS idx_branches_name ON branches (name);

                CREATE TABLE IF NOT EXISTS categories (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  description TEXT NULL,
                  status TEXT NOT NULL DEFAULT 'active',
                  is_active INTEGER NOT NULL DEFAULT 1,
                  CONSTRAINT categories_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT categories_company_name_unique UNIQUE (company_id, name),
                  CONSTRAINT categories_company_fk FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS categories_company_id_idx ON categories (company_id);
                CREATE INDEX IF NOT EXISTS idx_categories_company_id ON categories (company_id);

                CREATE TABLE IF NOT EXISTS products (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  category_id INTEGER NOT NULL,
                  sku TEXT NOT NULL,
                  barcode TEXT NULL,
                  name TEXT NOT NULL,
                  description TEXT NULL,
                  stock_minimum INTEGER NOT NULL DEFAULT 0,
                  status TEXT NOT NULL DEFAULT 'active',
                  is_active INTEGER NOT NULL DEFAULT 1,
                  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  CONSTRAINT products_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT products_company_sku_unique UNIQUE (company_id, sku),
                  CONSTRAINT products_category_fk FOREIGN KEY (company_id, category_id) REFERENCES categories (company_id, id)
                );
                CREATE INDEX IF NOT EXISTS products_company_id_idx ON products (company_id);
                CREATE INDEX IF NOT EXISTS products_company_category_id_idx ON products (company_id, category_id);
                CREATE INDEX IF NOT EXISTS products_company_sku_idx ON products (company_id, sku);
                CREATE UNIQUE INDEX IF NOT EXISTS products_company_barcode_unique ON products (company_id, barcode) WHERE barcode IS NOT NULL;

                CREATE TABLE IF NOT EXISTS suppliers (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  document_id TEXT NULL,
                  contact_email TEXT NULL,
                  phone TEXT NULL,
                  status TEXT NOT NULL DEFAULT 'active',
                  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  CONSTRAINT suppliers_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT suppliers_company_fk FOREIGN KEY (company_id) REFERENCES companies (id) ON DELETE CASCADE,
                  CONSTRAINT suppliers_company_document_id_unique UNIQUE (company_id, document_id)
                );
                CREATE INDEX IF NOT EXISTS idx_suppliers_company_id ON suppliers (company_id);

                CREATE TABLE IF NOT EXISTS purchase_orders (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  supplier_id INTEGER NOT NULL,
                  status TEXT NOT NULL DEFAULT 'created',
                  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                  CONSTRAINT purchase_orders_company_id_id_unique UNIQUE (company_id, id),
                  CONSTRAINT purchase_orders_supplier_fk FOREIGN KEY (company_id, supplier_id) REFERENCES suppliers (company_id, id)
                );
                CREATE INDEX IF NOT EXISTS purchase_orders_company_id_idx ON purchase_orders (company_id);
                CREATE INDEX IF NOT EXISTS purchase_orders_supplier_id_idx ON purchase_orders (company_id, supplier_id);

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

                CREATE TABLE IF NOT EXISTS refresh_tokens (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  token_hash TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at INTEGER NOT NULL,
                  used_at INTEGER NULL,
                  CONSTRAINT rt_company_token_unique UNIQUE (company_id, token_hash),
                  CONSTRAINT rt_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
                );
                CREATE INDEX IF NOT EXISTS rt_company_id_idx ON refresh_tokens (company_id);
                CREATE INDEX IF NOT EXISTS rt_user_id_idx ON refresh_tokens (user_id);
                CREATE INDEX IF NOT EXISTS rt_token_hash_idx ON refresh_tokens (token_hash);

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
                  (404, 'proveedores:editar', 'Editar proveedores'),
                  (500, 'compras:crear', 'Crear órdenes de compra'),
                  (501, 'compras:leer', 'Leer órdenes de compra'),
                  (502, 'compras:aprobar', 'Aprobar órdenes de compra'),
                  (600, 'reportes:leer', 'Leer reportes'),
                  (700, 'configuracion:modificar', 'Modificar configuración'),
                  (701, 'configuracion:leer', 'Leer configuración'),
                  (702, 'configuracion:editar', 'Editar configuración'),
                  (800, 'empresas:crear', 'Crear empresas'),
                  (801, 'empresas:leer', 'Leer empresas'),
                  (802, 'empresas:editar', 'Editar empresas'),
                  (810, 'sucursal:crear', 'Crear sucursales'),
                  (811, 'sucursales:leer', 'Leer sucursales'),
                  (812, 'sucursales:editar', 'Editar sucursales'),
                  (813, 'sucursales:eliminar', 'Eliminar (desactivar) sucursales');

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
                JOIN permissions p ON p.code NOT IN ('empresas:crear', 'empresas:leer', 'empresas:editar')
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
            if "default_branch_id" not in cols:
                conn.execute("ALTER TABLE companies ADD COLUMN default_branch_id INTEGER NULL")
            branch_cols = [row[1] for row in conn.execute("PRAGMA table_info(branches)").fetchall()]
            if "address" not in branch_cols:
                conn.execute("ALTER TABLE branches ADD COLUMN address TEXT NULL")
            if "city" not in branch_cols:
                conn.execute("ALTER TABLE branches ADD COLUMN city TEXT NULL")
            if "country" not in branch_cols:
                conn.execute("ALTER TABLE branches ADD COLUMN country TEXT NULL")
            if "status" not in branch_cols:
                conn.execute("ALTER TABLE branches ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            category_cols = [row[1] for row in conn.execute("PRAGMA table_info(categories)").fetchall()]
            if "description" not in category_cols:
                conn.execute("ALTER TABLE categories ADD COLUMN description TEXT NULL")
            if "status" not in category_cols:
                conn.execute("ALTER TABLE categories ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            product_cols = [row[1] for row in conn.execute("PRAGMA table_info(products)").fetchall()]
            if "stock_minimum" not in product_cols:
                conn.execute("ALTER TABLE products ADD COLUMN stock_minimum INTEGER NOT NULL DEFAULT 0")
            if "status" not in product_cols:
                conn.execute("ALTER TABLE products ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            if "created_at" not in product_cols:
                conn.execute("ALTER TABLE products ADD COLUMN created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))")
            if "updated_at" not in product_cols:
                conn.execute("ALTER TABLE products ADD COLUMN updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))")
            if "barcode" not in product_cols:
                conn.execute("ALTER TABLE products ADD COLUMN barcode TEXT NULL")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS products_company_barcode_unique ON products (company_id, barcode) WHERE barcode IS NOT NULL"
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO companies (id, name, currency, timezone, status, created_at, default_branch_id)
                VALUES
                  (1, 'Empresa 1', 'USD', 'UTC', 'active', strftime('%s','now'), NULL),
                  (2, 'Empresa 2', 'USD', 'UTC', 'active', strftime('%s','now'), NULL)
                """
            )
            conn.commit()
