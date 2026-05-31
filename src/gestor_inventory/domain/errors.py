class ValidationError(ValueError):
    pass


class EmailAlreadyExistsError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class PasswordResetTokenInvalidError(Exception):
    pass


class PasswordResetTokenExpiredError(Exception):
    pass
