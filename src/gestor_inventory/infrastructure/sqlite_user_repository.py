import sqlite3
from contextlib import contextmanager

from gestor_inventory.domain.errors import EmailAlreadyExistsError
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
                INSERT INTO audit_logs (company_id, branch_id, user_id, event_type, created_at, metadata_json)
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

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
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

                CREATE TABLE IF NOT EXISTS user_roles (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  role_id INTEGER NOT NULL,
                  CONSTRAINT user_roles_company_user_role_unique UNIQUE (company_id, user_id, role_id),
                  CONSTRAINT user_roles_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
                );
                CREATE INDEX IF NOT EXISTS user_roles_company_id_idx ON user_roles (company_id);
                CREATE INDEX IF NOT EXISTS user_roles_user_id_idx ON user_roles (user_id);

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

                CREATE TABLE IF NOT EXISTS audit_logs (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  branch_id INTEGER NULL,
                  user_id INTEGER NULL,
                  event_type TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  metadata_json TEXT NULL,
                  CONSTRAINT audit_logs_user_fk FOREIGN KEY (user_id) REFERENCES users (id)
                );
                CREATE INDEX IF NOT EXISTS audit_logs_company_id_idx ON audit_logs (company_id);
                CREATE INDEX IF NOT EXISTS audit_logs_company_created_at_idx ON audit_logs (company_id, created_at);
                CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx ON audit_logs (user_id);
                """
            )
