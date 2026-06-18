class ValidationError(ValueError):
    pass


class WeakPasswordError(ValidationError):
    pass


class CrossTenantReferenceError(ValidationError):
    pass


class SupplierNotFoundError(ValidationError):
    pass


class InvalidSupplierError(ValidationError):
    pass


class BranchHasInventoryError(Exception):
    pass


class ForbiddenError(Exception):
    pass


class NotFoundError(Exception):
    pass


class CompanyNameAlreadyExistsError(Exception):
    pass


class EmailAlreadyExistsError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class PasswordResetTokenInvalidError(Exception):
    pass


class PasswordResetTokenExpiredError(Exception):
    pass
