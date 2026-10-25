"""Typed, non-secret-bearing errors raised by security primitives."""


class SecurityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class PasswordError(SecurityError):
    pass


class SessionError(SecurityError):
    pass


class AuthorizationError(SecurityError):
    pass


class EncryptionError(SecurityError):
    pass

