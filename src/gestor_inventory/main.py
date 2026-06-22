import os
import secrets
from http.server import ThreadingHTTPServer

from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.infrastructure.resend_email_sender import (
    ResendVerificationEmailSender,
    UnavailableVerificationEmailSender,
)
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
    try:
        refresh_token_expiration_minutes = int(os.environ.get("JWT_REFRESH_EXPIRATION_MINUTES", "10080"))
    except ValueError:
        refresh_token_expiration_minutes = 10080
    if refresh_token_expiration_minutes <= 0:
        refresh_token_expiration_minutes = 10080

    repo = SqliteUserRepository(db_path=db_path)
    resend_api_key = os.environ.get("GI_RESEND_API_KEY", "").strip()
    from_email = os.environ.get("GI_EMAIL_FROM", "").strip()
    app_name = os.environ.get("GI_APP_NAME", "Gestor Inventory")
    reply_to = os.environ.get("GI_EMAIL_REPLY_TO")
    public_base_url = os.environ.get("GI_PUBLIC_BASE_URL")

    if resend_api_key and from_email:
        email_sender = ResendVerificationEmailSender(
            api_key=resend_api_key,
            from_email=from_email,
            app_name=app_name,
            reply_to=reply_to,
        )
    else:
        email_sender = UnavailableVerificationEmailSender()

    HttpApiHandler.repo = repo
    HttpApiHandler.jwt_secret = jwt_secret
    HttpApiHandler.jwt_expiration_minutes = jwt_expiration_minutes
    HttpApiHandler.refresh_token_expiration_minutes = refresh_token_expiration_minutes
    HttpApiHandler.email_sender = email_sender
    HttpApiHandler.public_base_url = public_base_url
    server = ThreadingHTTPServer((host, port), HttpApiHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
