"""Database exceptions with messages safe to expose to application code."""


class DatabaseError(Exception):
    """A database operation failed without exposing SQL or local paths."""

    def __init__(self, message: str = "Database operation failed") -> None:
        super().__init__(message)

