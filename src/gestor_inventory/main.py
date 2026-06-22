import os
import secrets
from http.server import ThreadingHTTPServer

from gestor_inventory.infrastructure.sqlite_sat_repository import SqliteSatRepository
from gestor_inventory.presentation.http_api import HttpApiHandler


def main() -> None:
    host = os.environ.get("GI_HOST", "127.0.0.1")
    port = int(os.environ.get("GI_PORT", "8000"))
    db_path = os.environ.get("GI_SQLITE_PATH", os.path.join(os.getcwd(), "gestor_inventory.sqlite3"))
    jwt_secret = os.environ.get("GI_JWT_SECRET") or secrets.token_urlsafe(32)
    try:
        jwt_expiration_minutes = int(os.environ.get("JWT_EXPIRATION_MINUTES", "60"))
    except ValueError:
        jwt_expiration_minutes = 60
    if jwt_expiration_minutes <= 0:
        jwt_expiration_minutes = 60

    repo = SqliteSatRepository(db_path=db_path)
    HttpApiHandler.repo = repo
    HttpApiHandler.jwt_secret = jwt_secret
    HttpApiHandler.jwt_expiration_minutes = jwt_expiration_minutes
    server = ThreadingHTTPServer((host, port), HttpApiHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
