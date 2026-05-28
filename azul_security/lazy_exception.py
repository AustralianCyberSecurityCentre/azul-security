"""Lazily load security exceptions."""

from typing import Any

from azul_bedrock.exception_enums import ExceptionCodeEnum

PARAMETER_TYPE = dict[str, str | int | float | bool] | dict[str, Any] | None


def lazy_is_security_exception(e: Exception):
    """Lazily raise an exception."""
    from azul_bedrock import exceptions_security

    if isinstance(e, exceptions_security.SecurityAccessException):
        return True
    elif isinstance(e, exceptions_security.SecurityConfigException):
        return True
    elif isinstance(e, exceptions_security.SecurityException):
        return True
    elif isinstance(e, exceptions_security.SecurityParseException):
        return True
    return False


def lazy_raise_SecurityAccessException(internal: ExceptionCodeEnum, ref: str = "", parameters: PARAMETER_TYPE = None):
    """Raise SecurityAccessException with a delayed import."""
    from azul_bedrock import exceptions_security

    raise exceptions_security.SecurityAccessException(internal=internal, ref=ref, parameters=parameters)


def lazy_raise_SecurityConfigException(internal: ExceptionCodeEnum, ref: str = "", parameters: PARAMETER_TYPE = None):
    """Raise SecurityConfigException with a delayed import."""
    from azul_bedrock import exceptions_security

    raise exceptions_security.SecurityConfigException(internal=internal, ref=ref, parameters=parameters)


def lazy_raise_SecurityException(internal: ExceptionCodeEnum, ref: str = "", parameters: PARAMETER_TYPE = None):
    """Raise SecurityException with a delayed import."""
    from azul_bedrock import exceptions_security

    raise exceptions_security.SecurityException(internal=internal, ref=ref, parameters=parameters)


def lazy_raise_SecurityParseException(internal: ExceptionCodeEnum, ref: str = "", parameters: PARAMETER_TYPE = None):
    """Raise SecurityParseException with a delayed import."""
    from azul_bedrock import exceptions_security

    raise exceptions_security.SecurityParseException(internal=internal, ref=ref, parameters=parameters)
