import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from gestor_inventory.application.login_user import LoginRequest, login_user
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.domain.errors import EmailAlreadyExistsError, InvalidCredentialsError, ValidationError


class HttpApiHandler(BaseHTTPRequestHandler):
    repo = None
    jwt_secret = None

    def do_POST(self):
        if self.path == "/api/users/register":
            self._handle_register()
            return
        if self.path == "/api/auth/login":
            self._handle_login()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _handle_register(self) -> None:
        try:
            payload = self._read_json()
            req = RegisterUserRequest(
                company_id=payload["company_id"],
                email=payload["email"],
                password=payload["password"],
                role_id=payload["role_id"],
            )
            res = register_user(self.repo, req)
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
            res = login_user(self.repo, req, jwt_secret=self.jwt_secret)
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

    def log_message(self, format, *args):
        return

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
