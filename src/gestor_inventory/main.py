import os
from http.server import ThreadingHTTPServer

from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.presentation.http_api import HttpApiHandler


def main() -> None:
    host = os.environ.get("GI_HOST", "127.0.0.1")
    port = int(os.environ.get("GI_PORT", "8000"))
    db_path = os.environ.get("GI_SQLITE_PATH", os.path.join(os.getcwd(), "gestor_inventory.sqlite3"))

    repo = SqliteUserRepository(db_path=db_path)
    HttpApiHandler.repo = repo
    server = ThreadingHTTPServer((host, port), HttpApiHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
