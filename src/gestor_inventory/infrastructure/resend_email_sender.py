import json
from typing import Protocol
from urllib import error, request


class EmailDeliveryError(Exception):
    pass


class VerificationEmailSender(Protocol):
    def send_verification_email(self, *, to_email: str, verification_url: str) -> None: ...


class NoopVerificationEmailSender:
    def send_verification_email(self, *, to_email: str, verification_url: str) -> None:
        return


class UnavailableVerificationEmailSender:
    def send_verification_email(self, *, to_email: str, verification_url: str) -> None:
        raise EmailDeliveryError("Servicio de correo no configurado")


class ResendVerificationEmailSender:
    def __init__(
        self,
        *,
        api_key: str,
        from_email: str,
        app_name: str = "Gestor Inventory",
        reply_to: str | None = None,
    ) -> None:
        self._api_key = str(api_key).strip()
        self._from_email = str(from_email).strip()
        self._app_name = str(app_name).strip() or "Gestor Inventory"
        self._reply_to = str(reply_to).strip() if isinstance(reply_to, str) and reply_to.strip() else None
        if not self._api_key:
            raise ValueError("api_key inválido")
        if not self._from_email:
            raise ValueError("from_email inválido")

    def send_verification_email(self, *, to_email: str, verification_url: str) -> None:
        payload = {
            "from": self._from_email,
            "to": [str(to_email)],
            "subject": f"Verifica tu cuenta en {self._app_name}",
            "html": _build_verification_html(app_name=self._app_name, verification_url=verification_url),
        }
        if self._reply_to is not None:
            payload["reply_to"] = self._reply_to

        raw = json.dumps(payload).encode("utf-8")
        req = request.Request(
            "https://api.resend.com/emails",
            data=raw,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with request.urlopen(req, timeout=10) as resp:
                status = int(getattr(resp, "status", 200))
                if status < 200 or status >= 300:
                    raise EmailDeliveryError("Respuesta inválida del proveedor de correo")
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise EmailDeliveryError(f"Resend devolvió HTTP {exc.code}: {body}") from exc
        except error.URLError as exc:
            raise EmailDeliveryError("No fue posible conectar con Resend") from exc


def _build_verification_html(*, app_name: str, verification_url: str) -> str:
    safe_app_name = str(app_name)
    safe_url = str(verification_url)
    return f"""
<html>
  <body style="font-family: Arial, sans-serif; color: #1f2937; line-height: 1.5;">
    <h2>Verifica tu cuenta</h2>
    <p>Recibimos una solicitud para activar tu acceso a {safe_app_name}.</p>
    <p>
      <a href="{safe_url}" style="display: inline-block; padding: 12px 18px; background: #2563eb; color: #ffffff; text-decoration: none; border-radius: 6px;">
        Verificar cuenta
      </a>
    </p>
    <p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
    <p><a href="{safe_url}">{safe_url}</a></p>
    <p>Este enlace expira en 24 horas.</p>
  </body>
</html>
""".strip()
