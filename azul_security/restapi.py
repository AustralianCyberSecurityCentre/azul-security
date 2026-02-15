"""Restapi endpoints for security."""

import functools

from azul_bedrock import exceptions_bedrock, exceptions_security
from azul_bedrock.exception_enums import ExceptionCodeEnum
from fastapi import APIRouter, Body, Request

from azul_security import admin, security, settings

router = APIRouter()


@functools.lru_cache()
def _get_sec():
    """Return an instance of the security class, cached."""
    return security.Security()


@router.get("/v0/security", response_model=settings.Settings)
def get_security_settings():
    """Return raw security settings."""
    return _get_sec()._s


@router.post("/v1/security/normalise", response_model=str)
def normalise_security(security: str = Body("", embed=True)):
    """Validate and normalise a security string.

    'ORG1 sloth//Low' -> 'LOW SLOTH ORG1'
    """
    try:
        sec = _get_sec().string_normalise(security)
    except exceptions_security.SecurityParseException as e:
        raise exceptions_bedrock.ApiException(
            status_code=400,
            ref=f"invalid security strings: {str(e)}",
            internal=ExceptionCodeEnum.SecurityNormaliseInvalidSecurity,
            parameters={"inner_exception": str(e)},
        ) from None
    return sec


@router.post("/v1/security/max", response_model=str)
def max_security_strings(
    secs: list[str],
):
    """Merge multiple security strings into most restrictive combination.

    It is possible for a combination to be generated that will restrict all access.
    In this case, an error will be raised.

    ['MEDIUM ORG1 ORG2', 'LOW ORG2', 'HIGH'] -> 'HIGH ORG2'

    ['MEDIUM ORG1', 'LOW ORG2', 'HIGH'] -> INVALID
    """
    # combine security dicts
    try:
        sec = _get_sec().string_combine(secs)
    except exceptions_security.SecurityParseException as e:
        raise exceptions_bedrock.ApiException(
            status_code=400,
            ref=f"invalid security strings or combination: {str(e)}",
            internal=ExceptionCodeEnum.SecurityInvalidMaxSecurity,
            parameters={"inner_exception": str(e)},
        ) from None
    # return security string
    if not sec:
        raise exceptions_bedrock.ApiException(
            status_code=400, ref="empty result", internal=ExceptionCodeEnum.SecurityEmptyResultForMaxSecurity
        )
    return sec


@router.get(
    "/v0/security/is_admin",
    response_model=bool,
)
async def is_user_admin_api(request: Request) -> bool:
    """Return true if the user is admin and false if they are not."""
    # user_info is set by azul-restapi-server
    try:
        user_info = request.state.user_info
    except AttributeError:
        raise exceptions_bedrock.ApiException(
            status_code=500,
            ref="user_info is not available on request.state",
            internal=ExceptionCodeEnum.SecurityUserInfoCannotBeAcquired,
        ) from None
    return admin.is_user_admin(user_info)
