"""Safe server-side error types."""


class ProtocolError(Exception):
    def __init__(self, code: str, message: str, request_id: str | None = None) -> None:
        self.code = code
        self.message = message
        self.request_id = request_id
        super().__init__(message)


class StorageError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class RequestError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class ConfigurationError(Exception):
    """Invalid local configuration, with no secrets or private paths in message."""

