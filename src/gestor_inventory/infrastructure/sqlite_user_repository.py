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
                """
            )
