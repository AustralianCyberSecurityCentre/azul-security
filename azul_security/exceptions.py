"""Exceptions raised by security module."""


class SecurityException(Exception):
    """Something went wrong with handling security."""

    pass


class SecurityConfigException(SecurityException):
    """The friendly config transform had errors."""

    pass


class SecurityParseException(SecurityException):
    """The friendly config transform had errors."""

    pass


class SecurityAccessException(SecurityException):
    """User not permitted to access object."""

    pass
