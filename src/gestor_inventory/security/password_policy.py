from gestor_inventory.domain.errors import WeakPasswordError


def validate_password_strength(password: str) -> None:
    if not isinstance(password, str) or not password:
        raise WeakPasswordError("La contraseña es obligatoria")

    errors: list[str] = []
    if len(password) < 8:
        errors.append("mínimo 8 caracteres")
    if not any(c.isupper() for c in password):
        errors.append("al menos una letra mayúscula")
    if not any(c.isdigit() for c in password):
        errors.append("al menos un número")
    if not any(not c.isalnum() for c in password):
        errors.append("al menos un carácter especial")

    if errors:
        raise WeakPasswordError("Contraseña débil: " + ", ".join(errors))

